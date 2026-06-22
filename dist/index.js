"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.run = run;
const core = __importStar(require("@actions/core"));
const fs = __importStar(require("fs"));
const axios_1 = __importStar(require("axios"));
const net_1 = require("net");
const client_secrets_manager_1 = require("@aws-sdk/client-secrets-manager");
const utils_1 = require("./utils");
const constants_1 = require("./constants");
/* istanbul ignore next */
function validateSubscription() {
    return __awaiter(this, void 0, void 0, function* () {
        var _a, _b;
        const eventPath = process.env.GITHUB_EVENT_PATH;
        let repoPrivate;
        if (eventPath && fs.existsSync(eventPath)) {
            const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
            repoPrivate = (_a = eventData === null || eventData === void 0 ? void 0 : eventData.repository) === null || _a === void 0 ? void 0 : _a.private;
        }
        const upstream = 'aws-actions/aws-secretsmanager-get-secrets';
        const action = process.env.GITHUB_ACTION_REPOSITORY;
        const docsUrl = 'https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions';
        core.info("");
        core.info("\u001b[1;36mStepSecurity Maintained Action\u001b[0m");
        core.info(`Secure drop-in replacement for ${upstream}`);
        if (repoPrivate === false)
            core.info("\u001b[32m\u2713 Free for public repositories\u001b[0m");
        core.info(`\u001b[36mLearn more:\u001b[0m ${docsUrl}`);
        core.info("");
        if (repoPrivate === false)
            return;
        const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com';
        const body = { action: action || '' };
        if (serverUrl !== 'https://github.com')
            body.ghes_server = serverUrl;
        try {
            yield axios_1.default.post(`https://agent.api.stepsecurity.io/v1/github/${process.env.GITHUB_REPOSITORY}/actions/maintained-actions-subscription`, body, { timeout: 3000 });
        }
        catch (error) {
            if ((0, axios_1.isAxiosError)(error) && ((_b = error.response) === null || _b === void 0 ? void 0 : _b.status) === 403) {
                core.error("\u001b[1;31mThis action requires a StepSecurity subscription for private repositories.\u001b[0m");
                core.error(`\u001b[31mLearn how to enable a subscription: ${docsUrl}\u001b[0m`);
                process.exit(1);
            }
            core.info('Timeout or API not reachable. Continuing to next step.');
        }
    });
}
function run() {
    return __awaiter(this, void 0, void 0, function* () {
        try {
            // Node 20 introduced automatic family selection for dual-stack endpoints. When the runner 
            // sits far away from the secrets manager endpoint it sometimes timeouts on negotiation between
            // A and AAAA records. This behaviour was described in the https://github.com/nodejs/node/issues/54359
            // The default value is 1s. We allow configuring this timeout through the
            // 'auto-select-family-attempt-timeout' parameter to help prevent flaky integration tests
            const timeout = Number(core.getInput('auto-select-family-attempt-timeout'));
            if (timeout < 10 || Number.isNaN(timeout)) {
                core.setFailed(`Invalid value for 'auto-select-family-attempt-timeout': ${timeout}. Must be a number greater than or equal to 10.`);
                return;
            }
            (0, net_1.setDefaultAutoSelectFamilyAttemptTimeout)(timeout);
            // Default client region is set by configure-aws-credentials
            const client = new client_secrets_manager_1.SecretsManagerClient({ region: process.env.AWS_DEFAULT_REGION, customUserAgent: (0, constants_1.getUserAgent)() });
            const secretConfigInputs = [...new Set(core.getMultilineInput('secret-ids'))];
            const parseJsonSecrets = core.getBooleanInput('parse-json-secrets');
            const nameTransformation = (0, utils_1.parseTransformationFunction)(core.getInput('name-transformation'));
            // Get final list of secrets to request
            core.info('Building secrets list...');
            const secretIds = yield (0, utils_1.buildSecretsList)(client, secretConfigInputs, nameTransformation);
            // Keep track of secret names that will need to be cleaned from the environment
            let secretsToCleanup = [];
            core.info('Your secret names may be transformed in order to be valid environment variables (see README). Enable Debug logging in order to view the new environment names.');
            // Get and inject secret values
            for (let secretId of secretIds) {
                //  Optionally let user set an alias, i.e. `ENV_NAME,secret_name`
                let secretAlias = undefined;
                [secretAlias, secretId] = (0, utils_1.extractAliasAndSecretIdFromInput)(secretId, nameTransformation);
                // Retrieves the secret name also, if the value is an ARN
                const isArn = (0, utils_1.isSecretArn)(secretId);
                try {
                    const secretValueResponse = yield (0, utils_1.getSecretValue)(client, secretId);
                    const secretValue = secretValueResponse.secretValue;
                    // Catch if blank prefix is specified but no json is parsed to avoid blank environment variable
                    if ((secretAlias === '') && !(parseJsonSecrets && (0, utils_1.isJSONString)(secretValue))) {
                        secretAlias = undefined;
                    }
                    if (secretAlias === undefined) {
                        secretAlias = isArn ? secretValueResponse.name : secretId;
                    }
                    const injectedSecrets = (0, utils_1.injectSecret)(secretAlias, secretValue, parseJsonSecrets, nameTransformation);
                    secretsToCleanup = [...secretsToCleanup, ...injectedSecrets];
                }
                catch (err) {
                    // Fail action for any error
                    core.setFailed(`Failed to fetch secret: '${secretId}'. Error: ${err}.`);
                }
            }
            // Get existing clean up list
            const existingCleanupSecrets = process.env[constants_1.CLEANUP_NAME];
            if (existingCleanupSecrets) {
                secretsToCleanup = [...JSON.parse(existingCleanupSecrets), ...secretsToCleanup];
            }
            // Export the names of variables to clean up after completion
            core.exportVariable(constants_1.CLEANUP_NAME, JSON.stringify(secretsToCleanup));
            core.info("Completed adding secrets.");
        }
        catch (error) {
            if (error instanceof Error)
                core.setFailed(error.message);
        }
    });
}
/* istanbul ignore next */
function main() {
    return __awaiter(this, void 0, void 0, function* () {
        yield validateSubscription();
        yield run();
    });
}
main();
