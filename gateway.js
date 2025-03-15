const fs = require('fs');
const path = require('path');
const https = require('https');
const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { ApolloGateway, IntrospectAndCompose, RemoteGraphQLDataSource } = require('@apollo/gateway');
const { ApolloServerPluginLandingPageLocalDefault } = require('@apollo/server/plugin/landingPage/default');
//const { createComplexityPlugin } = require('graphql-query-complexity');
const { createComplexityRule } = require('graphql-query-complexity')
//const responseCachePlugin = require('@apollo/server-plugin-response-cache');
const rateLimit = require('express-rate-limit');
const depthLimit = require('graphql-depth-limit');
const helmet = require('helmet');
const xss = require('xss-clean');
const { parse } = require('graphql');
require('dotenv').config();

const logger = {
    info: (message) => console.log(`[INFO] ${message}`),
    warn: (message) => console.warn(`[WARN] ${message}`),
    error: (message, err) => console.error(`[ERROR] ${message}`, err)
};

const SERVICE_CA_PATH = '/etc/ssl/certs/service-ca/service-ca.crt';
let secureAgent;

try {
    if (fs.existsSync(SERVICE_CA_PATH)) {
        const caCert = fs.readFileSync(SERVICE_CA_PATH);
        secureAgent = new https.Agent({
            ca: caCert
        });
        logger.info('Successfully loaded service CA certificate');
    } else {
        logger.warn('Service CA certificate not found at: ' + SERVICE_CA_PATH);
        secureAgent = new https.Agent();
    }
} catch (error) {
    logger.error('Error loading service CA certificate:', error);
    secureAgent = new https.Agent();
}

class SecureDataSource extends RemoteGraphQLDataSource {
    willSendRequest({ request, context }) {
        request.http = request.http || {};
        request.http.agent = secureAgent;

        if (request.variables) {
            request.variables = this.sanitizeVariables(request.variables);
        }

        if (context && context.clientIp) {
            request.http.headers = request.http.headers || {};
            request.http.headers['X-Forwarded-For'] = context.clientIp;
        }

        if (context && context.requestId) {
            request.http.headers = request.http.headers || {};
            request.http.headers['X-Request-ID'] = context.requestId;
        }
    }

    sanitizeVariables(variables) {
        if (!variables || typeof variables !== 'object') return variables;

        const sanitized = {};
        for (const [key, value] of Object.entries(variables)) {
            if (typeof value === 'string') {
                // Basic string sanitization to prevent SQL injection and XSS
                sanitized[key] = this.sanitizeString(value);
            } else if (Array.isArray(value)) {
                sanitized[key] = value.map(item =>
                    typeof item === 'object' ? this.sanitizeVariables(item) :
                        typeof item === 'string' ? this.sanitizeString(item) : item
                );
            } else if (value && typeof value === 'object') {
                sanitized[key] = this.sanitizeVariables(value);
            } else {
                sanitized[key] = value;
            }
        }
        return sanitized;
    }

    sanitizeString(str) {
        let sanitized = str.replace(/(\b)(on\S+)(\s*)=|javascript:|expression\s*\(|eval\s*\(|new\s+Function|document\.|window\.|alert|confirm|prompt/gi, '');

        sanitized = sanitized.replace(/('|"|\)|\(|;|--|\/\*|\*\/|\\)/g, match => `\\${match}`);

        return sanitized;
    }
}

const gateway = new ApolloGateway({
    supergraphSdl: new IntrospectAndCompose({
        subgraphs: [
            { name: 'order-service', url: "https://order-service-usecase-ace.apps.sandbox.id.internal/graphql" },
            { name: 'crm-service', url: "https://crm-proxy-usecase-ace.apps.sandbox.id.internal/graphql" },
            { name: 'product-service', url: "https://prisma-usecase-ace.apps.sandbox.id.internal/graphql" }
        ],
        introspectionHeaders: {
            'User-Agent': 'Apollo-Gateway'
        },
        logger: {
            debug: (message) => logger.info(`Composition: ${message}`),
            info: (message) => logger.info(`Composition: ${message}`),
            warn: (message) => logger.warn(`Composition: ${message}`),
            error: (message) => logger.error(`Composition: ${message}`)
        }
    }),
    serviceHealthCheck: true,
    buildService({ name, url }) {
        return new SecureDataSource({
            url,
            httpAgent: secureAgent,
            httpsAgent: secureAgent
        });
    }
});

const complexityRule = createComplexityRule({
    maximumComplexity: 1000,
    onComplete: (complexity) => {
        logger.info(`Query complexity: ${complexity}`);
    },
    createError: (max, actual) => {
        return new Error(`Query is too complex: ${actual}. Maximum allowed complexity: ${max}`);
    }
});

function validateQuery(query) {
    try {
        const parsedQuery = parse(query);
        const queryString = query.toString().toLowerCase();

        if (process.env.DISABLE_INTROSPECTION === 'true' &&
            (queryString.includes('__schema') || queryString.includes('__type'))) {
            throw new Error('Introspection queries are disabled');
        }

        const suspiciousPatterns = [
            'sleep(', 'benchmark(', 'pg_sleep', 'waitfor delay',
            'execute immediate', 'having 1=1', 'union select',
            'script>', '<script', 'onerror=', 'javascript:'
        ];

        for (const pattern of suspiciousPatterns) {
            if (queryString.includes(pattern)) {
                throw new Error('Potentially malicious query detected');
            }
        }

        return parsedQuery;
    } catch (error) {
        throw new Error(`Query validation failed: ${error.message}`);
    }
}

async function startGateway() {
    const server = new ApolloServer({
        gateway,
        subscriptions: false,
        introspection: process.env.NODE_ENV !== 'production', // Disable in production
        plugins: [
            {
                async requestDidStart(requestContext) {
                    try {
                        if (requestContext.request.query) {
                            validateQuery(requestContext.request.query);
                        }

                        const requestId = require('crypto').randomUUID();
                        requestContext.contextValue = {
                            ...requestContext.contextValue,
                            requestId
                        };

                        return {
                            async didResolveOperation({ request, document }) {
                                const maxDepth = 10;
                                const depths = depthLimit(maxDepth)(document, {}, {});

                                if (depths.length > 0) {
                                    throw new Error(`Query exceeds maximum depth of ${maxDepth}`);
                                }
                            },
                            async didEncounterErrors(requestContext) {
                                logger.error(`Request ${requestId} errors:`, requestContext.errors);
                            },
                            async willSendResponse(requestContext) {
                                logger.info(`Request ${requestId} completed: ${requestContext.request.operationName || 'anonymous operation'}`);
                            }
                        };
                    } catch (error) {
                        throw new Error(`Security validation failed: ${error.message}`);
                    }
                }
            },
            ApolloServerPluginLandingPageLocalDefault({ embed: true })
        ],
        validationRules: [
            depthLimit(10),
            complexityRule
        ],
        formatError: (error) => {
            logger.error('Formatted error:', error);
            if (process.env.NODE_ENV === 'production') {
                return new Error('Internal server error');
            }
            return error;
        }
    });

    const { url } = await startStandaloneServer(server, {
        listen: { port: process.env.GATEPORT || 4000 },
        context: async ({ req }) => {
            // Generate a unique request ID for tracing
            const requestId = require('crypto').randomUUID();

            return {
                clientIp: req.ip || req.connection.remoteAddress,
                userAgent: req.headers['user-agent'],
                requestId
            };
        },
        expressMiddleware: {
            app: undefined, // This will be created by startStandaloneServer
            path: '/',
            cors: {
                origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
                credentials: true,
                methods: ['POST', 'OPTIONS'], // Restrict to just what's needed
                allowedHeaders: ['Content-Type', 'Authorization'],
                maxAge: 86400, // 24 hours
            },
            onBeforeMiddleware: (app) => {
                const limiter = rateLimit({
                    windowMs: 15 * 60 * 1000, // 15 minutes
                    max: 100,
                    standardHeaders: true,
                    legacyHeaders: false,
                    message: 'Too many requests, please try again after 15 minutes',
                });
                app.use(limiter);

                app.use(helmet({
                    contentSecurityPolicy: {
                        directives: {
                            defaultSrc: ["'self'"],
                            scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline scripts for Apollo Explorer
                            styleSrc: ["'self'", "'unsafe-inline'"],  // Allow inline styles for Apollo Explorer
                            imgSrc: ["'self'", "data:"],
                            connectSrc: ["'self'"],
                            fontSrc: ["'self'"],
                            objectSrc: ["'none'"],
                            mediaSrc: ["'self'"],
                            frameSrc: ["'none'"],
                            workerSrc: ["'self'", "blob:"],  // Allow workers for Apollo Explorer
                        },
                    },
                    xssFilter: true,
                    noSniff: true,
                    hsts: {
                        maxAge: 31536000,
                        includeSubDomains: true,
                        preload: true
                    },
                    frameguard: {
                        action: 'deny'
                    },
                    referrerPolicy: { policy: 'same-origin' }
                }));

                app.use(xss());

                app.use(require('express').json({ limit: '100kb' }));

                app.use((req, res, next) => {
                    logger.info(`${req.method} ${req.originalUrl} - ${req.ip}`);
                    next();
                });

                app.use((req, res, next) => {
                    if (req.body && req.body.query) {
                        try {
                            const query = req.body.query.toLowerCase();
                            const suspiciousTerms = ['union select', 'information_schema', 'sleep(', '--', '/*', '*/'];

                            if (suspiciousTerms.some(term => query.includes(term))) {
                                return res.status(403).json({
                                    errors: [{ message: 'Forbidden query pattern detected' }]
                                });
                            }
                        } catch (error) {
                            logger.error('Error in security middleware:', error);
                        }
                    }
                    next();
                });
            }
        }
    });
    console.log(`🚀 Federated Gateway ready at ${url}`);
}

startGateway().catch(err => {
    console.error('Failed to start gateway:', err);
    process.exit(1);
});