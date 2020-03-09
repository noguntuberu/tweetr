/**
 * @author Oguntuberu Nathan O. <nateoguns.work@gmail.com>
**/
import TwitterHelper from './lib/TwitterHelper';
import * as axios from 'axios';
import * as crypto from 'crypto';

import RequestTokenResponse from './lib/interfaces/i-request-token-response';
import AccessTokenResponse from './lib/interfaces/i-access-token-response';
import BearerTokenResponse from './lib/interfaces/i-bearer-token-response';

class Tweetr extends TwitterHelper {
    private axios = axios.default;
    constructor() {
        super();
    }

    async obtain_bearer_token(): Promise<BearerTokenResponse> {
        const
        consumer_key = this.oauth_config.oauth_consumer_key,
        consumer_secret = this.oauth_config.oauth_consumer_secret,
        concatenated_secret = `${consumer_key}:${consumer_secret}`,
        encoded_secret = Buffer.from(concatenated_secret).toString('base64'),
        data = {
            grant_type: `client_credentials`
        },

        tokens: BearerTokenResponse = await this.axios.post(
            `https://api.twitter.com/oauth2/token?grant_type=client_credentials`,
            data,
            {
                headers: {
                    Authorization: `Basic ${encoded_secret}`,
                    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
                }
            }
        );

        return tokens
    }

    async obtain_request_token(): Promise<RequestTokenResponse> {
        this.set_configuration_method('post');
        this.set_configuration_uri(this.token_request_uri);

        const
        header_authorization_string = this.build_authorization_header(false),
        request_token_response = await this.axios.post(this.token_request_uri, {}, {
            headers: {
                Authorization: header_authorization_string
            }
        });
        

        return this.convert_token_string_to_object(request_token_response.data);
    }

    async obtain_access_token (query_string: string): Promise<AccessTokenResponse> {
        this.set_configuration_method('post');
        this.set_configuration_uri(this.token_access_uri);

        const
        header_authorization_string = this.build_authorization_header(false),
        access_token_response = await this.axios.post(`${this.token_access_uri}?${query_string}&Name=Description`, {

        }, {
            headers : {
                Authorization: header_authorization_string
            }
        });

        return this.convert_token_string_to_object(access_token_response.data);
    }

    async register_webhook (webhook_uri: string, environment_name: string) {
        const
        encoded_webhook_uri = this.percent_encode_string(webhook_uri),
        webhook_reg_uri = `https://api.twitter.com/1.1/account_activity/all/${environment_name}/webhooks.json`;

        this.set_configuration_method('post');
        this.set_configuration_uri(webhook_reg_uri);
        this.set_oauth_misc_values({ url: webhook_uri });
        this.patch_oauth_configuration_values({ oauth_callback: ''});

        const header_authorization_string = this.build_authorization_header(true);
        await this.axios.post(`${webhook_reg_uri}?url=${encoded_webhook_uri}`);
    }

    async verify_crc(crc: string): Promise<any> {
        const crc_hmac = crypto.createHmac('sha256', process.env.TWT_CONSUMER_SECRET);
        const crc_hmac_update = crc_hmac.update(crc);
        const response_token = crc_hmac_update.digest('base64');

        return {
            response_token: `sha256=${response_token}`
        }
    }
}

export default new Tweetr;