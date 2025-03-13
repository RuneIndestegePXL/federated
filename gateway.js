const fs = require('fs');
const path = require('path');
const https = require('https');
const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');
const { ApolloGateway, IntrospectAndCompose, RemoteGraphQLDataSource } = require('@apollo/gateway');
const { ApolloServerPluginLandingPageLocalDefault } = require('@apollo/server/plugin/landingPage/default');
require('dotenv').config();

const logger = {
    info: (message) => console.log(`[INFO] ${message}`),
    warn: (message) => console.warn(`[WARN] ${message}`),
    error: (message, err) => console.error(`[ERROR] ${message}`, err)
};

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const insecureAgent = new https.Agent({
    rejectUnauthorized: false
});

class CustomDataSource extends RemoteGraphQLDataSource {
    willSendRequest({ request }) {
        request.http = request.http || {};
        request.http.agent = insecureAgent;
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
        return new CustomDataSource({
            url,
            httpAgent: insecureAgent,
            httpsAgent: insecureAgent
        });
    }
});

async function startGateway() {
    const server = new ApolloServer({
        gateway,
        subscriptions: false,
        introspection: true,
        plugins: [
            {
                async requestDidStart(requestContext) {
                    logger.info(`Request started: ${requestContext.request.operationName || 'anonymous operation'}`);
                    return {
                        async didEncounterErrors(requestContext) {
                            logger.error('Errors during request execution:', requestContext.errors);
                        },
                        async willSendResponse(requestContext) {
                            if (requestContext.response.errors) {
                                logger.error('Response errors:', requestContext.response.errors);
                            }
                            logger.info(`Request completed: ${requestContext.request.operationName || 'anonymous operation'}`);
                        }
                    };
                }
            },
            ApolloServerPluginLandingPageLocalDefault({ embed: true })
        ],
        formatError: (error) => { logger.error('Formatted error:', error); return error; }
    });

    const { url } = await startStandaloneServer(server, {
        listen: { port: process.env.GATEPORT || 4000 }
    });
    console.log(`🚀 Federated Gateway ready at ${url}`);
}

startGateway().catch(err => {
    console.error('Failed to start gateway:', err);
    process.exit(1);
});