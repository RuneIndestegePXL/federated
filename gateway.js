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

const certificatePath = '/etc/ssl/certs/ca-bundle.crt';
const ca = fs.readFileSync(certificatePath);

const secureAgent = new https.Agent({
    ca,
    rejectUnauthorized: false,
    checkServerIdentity: () => undefined
});

class CustomDataSource extends RemoteGraphQLDataSource {
    willSendRequest({ request }) {
        request.http = request.http || {};
        request.http.agent = secureAgent;
    }
}

const gateway = new ApolloGateway({
    supergraphSdl: new IntrospectAndCompose({
        subgraphs: [
            { name: 'order-service', url: "https://order-service-usecase-ace.apps.sandbox.id.internal/graphql" },
            { name: 'crm-service', url: "https://crm-proxy-usecase-ace.apps.sandbox.id.internal/graphql" },
            { name: 'product-service', url: "https://prisma-usecase-ace.apps.sandbox.id.internal/graphql" }
        ],
        logger: {
            debug: (message) => logger.info(`Composition: ${message}`),
            info: (message) => logger.info(`Composition: ${message}`),
            warn: (message) => logger.warn(`Composition: ${message}`),
            error: (message) => logger.error(`Composition: ${message}`)
        }
    }),
    buildService({ name, url }) { return new CustomDataSource({ url }); }
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
        listen: { port: process.env.GATEPORT || 4000 },
        context: async ({ req }) => {
            logger.info(`Request headers: ${JSON.stringify(req.headers, null, 2)}`);
            return {};
        }
    });
    console.log(`🚀 Federated Gateway ready at ${url}`);
}

startGateway().catch(err => {
    console.error('Failed to start gateway:', err);
    process.exit(1);
});