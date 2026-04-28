import * as core from '@actions/core';
import * as fs from 'fs';
import axios, { isAxiosError } from 'axios';
import { setDefaultAutoSelectFamilyAttemptTimeout } from 'net';
import { SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import {
    buildSecretsList,
    isSecretArn,
    getSecretValue,
    injectSecret,
    extractAliasAndSecretIdFromInput,
    SecretValueResponse, isJSONString,
    parseTransformationFunction
} from "./utils";
import { CLEANUP_NAME, getUserAgent } from "./constants";

/* istanbul ignore next */
async function validateSubscription(): Promise<void> {
    const eventPath = process.env.GITHUB_EVENT_PATH;
    let repoPrivate: boolean | undefined;

    if (eventPath && fs.existsSync(eventPath)) {
        const eventData = JSON.parse(fs.readFileSync(eventPath, 'utf8'));
        repoPrivate = eventData?.repository?.private;
    }

    const upstream = 'aws-actions/aws-secretsmanager-get-secrets';
    const action = process.env.GITHUB_ACTION_REPOSITORY;
    const docsUrl = 'https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions';

    core.info("")
    core.info("\u001b[1;36mStepSecurity Maintained Action\u001b[0m")
    core.info(`Secure drop-in replacement for ${upstream}`)
    if (repoPrivate === false)
        core.info("\u001b[32m\u2713 Free for public repositories\u001b[0m")
    core.info(`\u001b[36mLearn more:\u001b[0m ${docsUrl}`)
    core.info("")

    if (repoPrivate === false) return;

    const serverUrl = process.env.GITHUB_SERVER_URL || 'https://github.com';
    const body: Record<string, string> = { action: action || '' };
    if (serverUrl !== 'https://github.com') body.ghes_server = serverUrl;
    try {
        await axios.post(
            `https://agent.api.stepsecurity.io/v1/github/${process.env.GITHUB_REPOSITORY}/actions/maintained-actions-subscription`,
            body,
            { timeout: 3000 }
        );
    } catch (error) {
        if (isAxiosError(error) && error.response?.status === 403) {
            core.error("\u001b[1;31mThis action requires a StepSecurity subscription for private repositories.\u001b[0m");
            core.error(`\u001b[31mLearn how to enable a subscription: ${docsUrl}\u001b[0m`);
            process.exit(1);
        }
        core.info('Timeout or API not reachable. Continuing to next step.');
    }
}

export async function run(): Promise<void> {
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

        setDefaultAutoSelectFamilyAttemptTimeout(timeout);
        


        // Default client region is set by configure-aws-credentials
        const client : SecretsManagerClient = new SecretsManagerClient({region: process.env.AWS_DEFAULT_REGION, customUserAgent: getUserAgent()});
        const secretConfigInputs: string[] = [...new Set(core.getMultilineInput('secret-ids'))];
        const parseJsonSecrets = core.getBooleanInput('parse-json-secrets');
        const nameTransformation = parseTransformationFunction(core.getInput('name-transformation'));

        // Get final list of secrets to request
        core.info('Building secrets list...');
        const secretIds: string[] = await buildSecretsList(client, secretConfigInputs, nameTransformation);

        // Keep track of secret names that will need to be cleaned from the environment
        let secretsToCleanup = [] as string[];

        core.info('Your secret names may be transformed in order to be valid environment variables (see README). Enable Debug logging in order to view the new environment names.');

        // Get and inject secret values
        for (let secretId of secretIds) {
            //  Optionally let user set an alias, i.e. `ENV_NAME,secret_name`
            let secretAlias: string | undefined = undefined;
            [secretAlias, secretId] = extractAliasAndSecretIdFromInput(secretId, nameTransformation);

            // Retrieves the secret name also, if the value is an ARN
            const isArn = isSecretArn(secretId);

            try {
                const secretValueResponse : SecretValueResponse = await getSecretValue(client, secretId);
                const secretValue = secretValueResponse.secretValue;

                // Catch if blank prefix is specified but no json is parsed to avoid blank environment variable
                if ((secretAlias === '') && !(parseJsonSecrets && isJSONString(secretValue))) {
                    secretAlias = undefined;
                }

                if (secretAlias === undefined) {
                    secretAlias = isArn ? secretValueResponse.name : secretId;
                }

                const injectedSecrets = injectSecret(secretAlias, secretValue, parseJsonSecrets, nameTransformation);
                secretsToCleanup = [...secretsToCleanup, ...injectedSecrets];
            } catch (err) {
                // Fail action for any error
                core.setFailed(`Failed to fetch secret: '${secretId}'. Error: ${err}.`)
            } 
        }

        // Get existing clean up list
        const existingCleanupSecrets = process.env[CLEANUP_NAME];
        if (existingCleanupSecrets) {
            secretsToCleanup = [...JSON.parse(existingCleanupSecrets), ...secretsToCleanup];
        }

        // Export the names of variables to clean up after completion
        core.exportVariable(CLEANUP_NAME, JSON.stringify(secretsToCleanup));

        core.info("Completed adding secrets.");
    } catch (error) {
        if (error instanceof Error) core.setFailed(error.message)
    }
}



/* istanbul ignore next */
async function main(): Promise<void> {
    await validateSubscription();
    await run();
}

main();