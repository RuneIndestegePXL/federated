const fs = require('fs');
const path = require('path');
const https = require('https');
const { ApolloServer } = require('@apollo/server');
const { ApolloGateway, IntrospectAndCompose, RemoteGraphQLDataSource } = require('@apollo/gateway');
const { ApolloServerPluginLandingPageLocalDefault } = require('@apollo/server/plugin/landingPage/default');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss-clean');
const { parse } = require('graphql');
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
/*
// Add safeguards against "find" issue - patch Array and Object prototypes
// This is an extreme measure but might help identify where the error is happening
const originalArrayFind = Array.prototype.find;
Array.prototype.find = function() {
    try {
        if (!this) {
            logger.error('Array.find called on null or undefined!', new Error().stack);
            return undefined;
        }
        return originalArrayFind.apply(this, arguments);
    } catch (e) {
        logger.error('Error in Array.find!', e);
        return undefined;
    }
};
*/

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
                {
                    async requestDidStart() {
                        return {
                            async willSendResponse(requestContext) {
                                if (requestContext.errors) {
                                    logger.error('GraphQL errors:', requestContext.errors);
                                }
                            }
                        };
                    }
                }
            ],
            formatError: (error) => {
                logger.error('GraphQL error:', error);
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
        //contentSecurityPolicy: false
    }));

    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 100,
        skipFailedRequests: true,
        validate: { trustProxy: false }
    });
    app.use(limiter);
    
    app.set('trust proxy', 1);
    app.use(xss());
    app.use(express.json({ limit: '100kb' }));

    app.use('/',
        cors(),
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
        res.status(500).json({ error: 'Internal server error' });
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