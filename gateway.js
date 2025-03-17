const fs = require('fs');
const path = require('path');
const https = require('https');
const { ApolloServer } = require('@apollo/server');
const { ApolloGateway, IntrospectAndCompose, RemoteGraphQLDataSource } = require('@apollo/gateway');
const { ApolloServerPluginLandingPageLocalDefault } = require('@apollo/server/plugin/landingPage/default');
const { createComplexityRule } = require('graphql-query-complexity');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss-clean');
const { parse, validate, specifiedRules } = require('graphql');
const {expressMiddleware} = require("@apollo/server/express4");
const express = require('express');
const cors = require('cors');
require('dotenv').config();

const logger = {
    info: (message) => console.log(`[INFO] ${message}`),
    warn: (message) => console.warn(`[WARN] ${message}`),
    error: (message, err) => {
        if (err && err.stack) {
            console.error(`[ERROR] ${message}`, err);
            console.error(`[ERROR STACK] ${err.stack}`);
        } else {
            console.error(`[ERROR] ${message}`, err || '');
        }
    },
    debug: (message) => console.log(`[DEBUG] ${message}`)
};

const SERVICE_CA_PATH = '/run/secrets/kubernetes.io/serviceaccount/service-ca.crt';
let secureAgent;

try {
    if (fs.existsSync(SERVICE_CA_PATH)) {
        const caCert = fs.readFileSync(SERVICE_CA_PATH);
        secureAgent = new https.Agent({
            ca: caCert,
            rejectUnauthorized: false 
        });
        logger.info('Successfully loaded service CA certificate');
    } else {
        logger.warn('Service CA certificate not found at: ' + SERVICE_CA_PATH);
        secureAgent = new https.Agent({
            rejectUnauthorized: false 
        });
    }
} catch (error) {
    logger.error('Error loading service CA certificate:', error);
    secureAgent = new https.Agent({
        rejectUnauthorized: false
    });
}

class SecureDataSource extends RemoteGraphQLDataSource {
    willSendRequest({ request, context }) {
        request.http = request.http || {};
        request.http.agent = secureAgent;

        if (context && context.clientIp) {
            request.http.headers = request.http.headers || {};
            request.http.headers['X-Forwarded-For'] = context.clientIp;
        }

        if (context && context.requestId) {
            request.http.headers = request.http.headers || {};
            request.http.headers['X-Request-ID'] = context.requestId;
        }
    }
}

const gateway = new ApolloGateway({
    debug: true, 
    __exposeQueryPlanExperimental: true, 
    supergraphSdl: new IntrospectAndCompose({
        subgraphs: [
            { name: 'order-service', url: "http://order-service.usecase-ace.svc.cluster.local:8080/graphql" },
            { name: 'crm-proxy', url: "http://crm-proxy.usecase-ace.svc.cluster.local:8083/graphql" },
            { name: 'product-service', url: "http://prisma.usecase-ace.svc.cluster.local:4001/graphql" }
        ],
        introspectionHeaders: {
            'User-Agent': 'Apollo-Gateway'
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

function createDepthLimitRule(maxDepth) {
    return function customDepthLimit(context) {
        const { definitions } = context.getDocument();

        function calculateDepth(selectionSet, depth = 0) {
            if (!selectionSet) return depth;
            
            let maxDepthFound = depth;
            
            for (const selection of selectionSet.selections) {
                if (selection.kind === 'Field') {
                    if (selection.name.value === '__typename') continue;
                    
                    if (selection.selectionSet) {
                        const fieldDepth = calculateDepth(selection.selectionSet, depth + 1);
                        maxDepthFound = Math.max(maxDepthFound, fieldDepth);
                    }
                } else if (selection.kind === 'InlineFragment' && selection.selectionSet) {
                    const fragmentDepth = calculateDepth(selection.selectionSet, depth);
                    maxDepthFound = Math.max(maxDepthFound, fragmentDepth);
                }
            }
            
            return maxDepthFound;
        }

        for (const def of definitions) {
            if (def.kind === 'OperationDefinition' && def.selectionSet) {
                const depth = calculateDepth(def.selectionSet);
                if (depth > maxDepth) {
                    context.reportError(
                        new Error(`Query exceeds maximum depth of ${maxDepth}. Got depth of ${depth}.`)
                    );
                }
            }
        }
        
        return context;
    };
}

function createSafeComplexityRule(options) {
    const originalRule = createComplexityRule(options);
    
    return function safeComplexityRule(validationContext) {
        try {
            if (!validationContext) {
                logger.warn('ValidationContext is undefined in complexity rule');
                return validationContext;
            }
            return originalRule(validationContext);
        } catch (error) {
            logger.error('Error in complexity rule:', error);
            return validationContext;
        }
    };
}

const complexityRule = createSafeComplexityRule({
    maximumComplexity: 1000,
    variables: {},
    onComplete: (complexity) => {
        logger.info(`Query complexity: ${complexity}`);
    },
    createError: (max, actual) => {
        return new Error(`Query is too complex: ${actual}. Maximum allowed complexity: ${max}`);
    }
});

function createSafeDepthLimitRule(maxDepth) {
    return function customDepthLimit(validationContext) {
        try {
            if (!validationContext || typeof validationContext.getDocument !== 'function') {
                logger.warn('ValidationContext is invalid in depth limit rule');
                return validationContext;
            }
            
            const doc = validationContext.getDocument();
            if (!doc || !doc.definitions) {
                logger.warn('Document is invalid in depth limit rule');
                return validationContext;
            }
            
            
            return validationContext;
        } catch (error) {
            logger.error('Error in depth limit rule:', error);
            return validationContext;
        }
    };
}

function validateQuery(query) {
    try {
        const parsedQuery = parse(query);
        const queryString = query.toLowerCase();
        
        const sqlPatterns = [
            'union select', 'select *', 'select 1', 'select @@version',
            'waitfor delay', 'sleep(', 'benchmark(', 'pg_sleep',
            'having 1=1', 'or 1=1', 'and 1=1',
            'exec ', 'execute ', 'sp_executesql',
            'insert into', 'update set', 'delete from',
            'drop table', 'drop database', 'create table',
            'alter table', 'sys.tables', 'information_schema',
            '--', '/*', '*/", "#', '\'\'=\'\''
        ];
        
        const xssPatterns = [
            '<script>', '</script>', 'javascript:', 'onerror=',
            'onload=', 'eval(', 'document.cookie', 'alert(',
            'String.fromCharCode(', 'fromCharCode',
            'expression(', 'url(javascript', '<img src=',
            'document.write', 'window.location'
        ];
        
        const injectionPatterns = [...sqlPatterns, ...xssPatterns];
        
        for (const pattern of injectionPatterns) {
            if (queryString.includes(pattern)) {
                logger.warn(`Security pattern detected in query: ${pattern}`);
                throw new Error('Potentially malicious query detected');
            }
        }
        
        return parsedQuery;
    } catch (error) {
        logger.error('Query validation error:', error);
        throw new Error(`Query validation failed: ${error.message}`);
    }
}

function calculateQueryDepth(document, maxDepth = 10) {
    try {
        if (!document || !document.definitions) {
            return { depth: 0, exceedsLimit: false };
        }

        function getDepth(selectionSet, currentDepth = 0) {
            if (!selectionSet || !selectionSet.selections || currentDepth > maxDepth) {
                return currentDepth;
            }
            
            let maxCurrentDepth = currentDepth;
            
            for (const selection of selectionSet.selections) {
                if (selection.kind === 'Field') {
                    if (selection.name.value.startsWith('__')) {
                        continue;
                    }
                    
                    if (selection.selectionSet) {
                        const fieldDepth = getDepth(selection.selectionSet, currentDepth + 1);
                        maxCurrentDepth = Math.max(maxCurrentDepth, fieldDepth);
                    }
                } else if (
                    (selection.kind === 'InlineFragment' || selection.kind === 'FragmentSpread') && 
                    selection.selectionSet
                ) {
                    const fragmentDepth = getDepth(selection.selectionSet, currentDepth);
                    maxCurrentDepth = Math.max(maxCurrentDepth, fragmentDepth);
                }
            }
            
            return maxCurrentDepth;
        }
        
        let maxDepthFound = 0;
        for (const def of document.definitions) {
            if (def.kind === 'OperationDefinition' && def.selectionSet) {
                const depth = getDepth(def.selectionSet);
                maxDepthFound = Math.max(maxDepthFound, depth);
            }
        }
        
        return { 
            depth: maxDepthFound, 
            exceedsLimit: maxDepthFound > maxDepth 
        };
    } catch (error) {
        logger.error('Error in depth calculation:', error);
        return { depth: 0, exceedsLimit: false };
    }
}

function calculateQueryComplexity(document, maxComplexity = 1000) {
    try {
        if (!document || !document.definitions) {
            return { complexity: 0, exceedsLimit: false };
        }
        
        let totalComplexity = 0;
        
        function countFields(selectionSet) {
            if (!selectionSet || !selectionSet.selections) return 0;
            
            let count = 0;
            for (const selection of selectionSet.selections) {
                if (selection.kind === 'Field') {
                    count += 1;
                    
                    if (selection.arguments && selection.arguments.length > 0) {
                        count += selection.arguments.length;
                    }
                    
                    if (selection.selectionSet) {
                        count += countFields(selection.selectionSet) * 1.5;
                    }
                } else if (
                    (selection.kind === 'InlineFragment' || selection.kind === 'FragmentSpread') && 
                    selection.selectionSet
                ) {
                    count += countFields(selection.selectionSet);
                }
            }
            
            return count;
        }
        for (const def of document.definitions) {
            if (def.kind === 'OperationDefinition' && def.selectionSet) {
                totalComplexity += countFields(def.selectionSet);
            }
        }
        
        return { 
            complexity: Math.round(totalComplexity), 
            exceedsLimit: totalComplexity > maxComplexity 
        };
    } catch (error) {
        logger.error('Error in complexity calculation:', error);
        return { complexity: 0, exceedsLimit: false }; 
    }
}

// depth and complexity limits, imported caused error
const queryLimitsPlugin = {
    async requestDidStart(requestContext) {
        return {
            async didResolveOperation(requestContext) {
                try {
                    const { document } = requestContext;
                    
                    if (!document) return;
                    
                    const maxDepth = 10;
                    const depthResult = calculateQueryDepth(document, maxDepth);
                    logger.info(`Query depth: ${depthResult.depth}`);
                    
                    if (depthResult.exceedsLimit) {
                        throw new Error(`Query depth of ${depthResult.depth} exceeds maximum depth of ${maxDepth}`);
                    }
                    const maxComplexity = 1000;
                    const complexityResult = calculateQueryComplexity(document, maxComplexity);
                    logger.info(`Query complexity: ${complexityResult.complexity}`);
                    
                    if (complexityResult.exceedsLimit) {
                        throw new Error(`Query complexity of ${complexityResult.complexity} exceeds maximum allowed complexity of ${maxComplexity}`);
                    }
                } catch (error) {
                    if (error.message.includes('exceeds maximum')) {
                        throw error;
                    } else {
                        logger.error('Error checking query limits:', error);
                    }
                }
            }
        };
    }
};

async function startGateway() {
    let server;

    try {
        process.on('unhandledRejection', (reason, promise) => {
            logger.error('Unhandled Rejection at:', reason);
        });
        server = new ApolloServer({
            gateway,
            introspection: true,
            plugins: [
                ApolloServerPluginLandingPageLocalDefault({ embed: true }),
                queryLimitsPlugin, 
                {
                    async requestDidStart() {
                        return {
                            async willSendResponse(requestContext) {
                                if (requestContext.errors) {
                                    logger.error('GraphQL errors:', requestContext.errors);
                                }
                            },
                            async didReceiveOperation({ request, document }) {
                                try {
                                    if (request.query) {
                                        validateQuery(request.query);
                                    }
                                } catch (error) {
                                    throw new Error(`Security validation failed: ${error.message}`);
                                }
                            }
                        };
                    }
                }
            ],
            validationRules: [],
            formatError: (error) => {
                if (error.message && error.message.includes('find')) {
                    logger.error('FIND ERROR DETECTED - Full context:', error);
                    try {
                        throw new Error('Stack trace for find error');
                    } catch (e) {
                        logger.error('Stack trace at find error point:', e.stack);
                    }
                }
                
                logger.error('GraphQL error:', error);
                if (process.env.NODE_ENV === 'production') {
                    return new Error('Internal server error');
                }
                return error;
            }
        });
        
        await server.start();
    } catch (error) {
        logger.error('Error initializing Apollo Server:', error);
        throw error;
    }

    const app = express();
    app.use('/graphql', (req, res, next) => {
        if (req.method === 'POST' && req.body && req.body.query) {
            try {
                logger.debug('Pre-Apollo GraphQL request:', req.body.query.substring(0, 100));
                try {
                    const parsedQuery = parse(req.body.query);
                    logger.debug('Query parsed successfully');
                } catch (parseError) {
                    logger.error('Query parse error:', parseError);
                }
            } catch (error) {
                logger.error('Error in diagnostics middleware:', error);
            }
        }
        next();
    });

    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", "data:"],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"],
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

    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 150,
        standardHeaders: true,
        legacyHeaders: false,
        message: 'Too many requests, please try again after 15 minutes',
        skipFailedRequests: true,
        keyGenerator: (req) => {
            return req.ip || req.socket.remoteAddress || '127.0.0.1';
        },
        validate: { trustProxy: false }
    });
    app.use(limiter);
    
    app.set('trust proxy', 1);
    app.use(xss());
    app.use(express.json({ 
        limit: '100kb',
        verify: (req, res, buf) => {
            try {
                JSON.parse(buf);
            } catch (e) {
                res.status(400).json({ errors: [{ message: 'Invalid JSON' }] });
                throw new Error('Invalid JSON');
            }
        }
    }));

    app.use((req, res, next) => {
        logger.info(`${req.method} ${req.path} - ${req.ip}`);
        next();
    });
    
    app.use((req, res, next) => {
        if (req.body && req.body.query && typeof req.body.query === 'string') {
            try {
                const query = req.body.query;
                validateQuery(query);                
            } catch (error) {
                logger.error('Query validation error in middleware:', error);
                return res.status(400).json({
                    errors: [{ message: error.message || 'Invalid query' }]
                });
            }
        }
        next();
    });

    app.use('/',
        cors({
            origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
            methods: ['POST', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization'],
            maxAge: 86400
        }),
        expressMiddleware(server, {
            context: async ({ req }) => ({
                clientIp: req.ip || '127.0.0.1',
                userAgent: req.headers ? req.headers['user-agent'] : undefined,
                requestId: require('crypto').randomUUID()
            })
        })
    );

    app.use((err, req, res, next) => {
        logger.error('Express error:', err);
        res.status(500).json({ errors: [{ message: 'Internal server error' }] });
    });

    const port = process.env.GATEPORT || 4000;
    app.listen(port, () => {
        console.log(`🚀 Federated Gateway ready at http://url:${port}`);
    });
}

startGateway().catch(err => {
    console.error('Failed to start gateway:', err);
    process.exit(1);
});