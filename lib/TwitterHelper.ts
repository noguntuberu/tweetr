/**
 * @author Oguntuberu Nathan O. <nateoguns.work@gmail.com>
**/
import * as crypto from 'crypto';
import * as hmac from 'hmacsha1';
import HeaderConfiguration from './interfaces/i-header-config';

class TwitterHelper {
    protected base_uri: string = `https://api.twitter.com/oauth`;
    protected token_request_uri: string = `${this.base_uri}/request_token`;
    protected token_access_uri: string = `${this.base_uri}/access_token`;
    protected http_method: string;
    protected request_uri: string;
    protected oauth_config: HeaderConfiguration;
    protected oauth_misc: any;
    protected dictionary: any = {
        0: '0', 1: '1', 2: '2', 3: '3', 4: '4', 5: '5', 6: '6', 7: '7', 8: '8', 9: '9',

        'A': 'A', 'B': 'B', 'C': 'C', 'D': 'D', 'E': 'E', 'F': 'F', 'G': 'G', 'H': 'H',
        'I': 'I', 'J': 'J', 'K': 'K', 'L': 'L', 'M': 'M', 'N': 'N', 'O': 'O', 'P': 'P',
        'Q': 'Q', 'R': 'R', 'S': 'S', 'T': 'T', 'U': 'U', 'V': 'V', 'W': 'W', 'X': 'X',
        'Y': 'Y', 'Z': 'Z', 'a': 'a', 'b': 'b', 'c': 'c', 'd': 'd', 'e': 'e', 'f': 'f',
        'g': 'g', 'h': 'h', 'i': 'i', 'j': 'j', 'k': 'k', 'l': 'l', 'm': 'm', 'n': 'n',
        'o': 'o', 'p': 'p', 'q': 'q', 'r': 'r', 's': 's', 't': 't', 'u': 'u', 'v': 'v',
        'w': 'w', 'x': 'x', 'y': 'y', 'z': 'z', '-': '-', '.': '.', '_': '_', '~': '~'
    }

    constructor() {

    }

    set_configuration_method(http_method: string) {
        this.http_method = http_method.toUpperCase();
    }

    set_configuration_uri(request_uri: string) {
        this.request_uri = request_uri;
    }

    set_oauth_configuration_values(config: HeaderConfiguration) {
        this.oauth_config = config;
    }

    set_oauth_misc_values(config: any) {
        this.oauth_misc = config;
    }

    patch_oauth_configuration_values(config: HeaderConfiguration) {
        this.oauth_config = {
            ...this.oauth_config,
            ...config
        };
    }

    delete_oauth_configuration_variable(variable_name: string) {
        delete this.oauth_config[variable_name];
    }

    /**
     * 
    **/

    generate_random_string(length: number): string {
        let result = '';
        let characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let characters_length = characters.length;
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * characters_length));
        }

        return result;
    }

    generate_nonce(): string {
        const nonce = Buffer.from(this.generate_random_string(32), 'ascii').toString('base64');
        return nonce.replace(/\W/g, '');
    }

    convert_token_string_to_object(token_string: string): any {
        let
        token_groups = token_string.split('&'),
        tokens = {};

        token_groups.forEach(token_group => {
            const token_pair = token_group.split('=');
            tokens[token_pair[0]] = token_pair[1];
        });

        return tokens;
    }

    convert_value_to_base_16(value: number): string {
        const char_representations = { 10: 'A', 11: 'B', 12: 'C', 13: 'D', 14: 'E', 15: 'F' };
        let base_16_string: string = ``,
            dividend: number = value,
            remainder: number = 0;

        while (dividend > 0) {
            if (dividend >= 16) {
                dividend = Math.trunc(value / 16);
                remainder = value - (dividend * 16);
            } else {
                remainder = dividend;
                dividend = 0;
            }

            const b_16_value = remainder > 9 ? char_representations[remainder] : remainder;
            base_16_string = `${b_16_value}${base_16_string}`;
        }

        //
        return base_16_string;
    }

    percent_encode_character(character: string): string {
        let percent_encoded_string: string = ``;
        const buffered_character = Buffer.from(character);

        for (let i = 0; i < buffered_character.length; i++) {
            const percented_character = `%${this.convert_value_to_base_16(buffered_character[i])}`;
            percent_encoded_string = `${percent_encoded_string}${percented_character}`;
        }

        return percent_encoded_string;
    }

    percent_encode_string(string_to_encode: string): string {
        if (string_to_encode === undefined) return '';
        let encoded_string: string = ``;

        for (let i = 0; i < string_to_encode.length; i++) {
            const current_character = string_to_encode[i];
            if (this.dictionary[current_character] !== undefined) {
                encoded_string = `${encoded_string}${current_character}`;
                continue;
            }

            const percent_encoded_character = this.percent_encode_character(current_character);
            encoded_string = `${encoded_string}${percent_encoded_character}`;
        }

        return encoded_string;
    }

    percent_encode_configuration_object(config_object: HeaderConfiguration): any {
        let encoded_configuration_object: any = {};

        for (let key in config_object) {
            const config_value = this.percent_encode_string(config_object[key].toString());
            const config_key = this.percent_encode_string(key);

            encoded_configuration_object = {
                ...encoded_configuration_object,
                [config_key]: config_value
            }
        }

        return encoded_configuration_object;
    }

    sort_configuration_keys(config_keys: Array<string>): Array<string> {
        return config_keys.sort();
    }

    flatten_configuration_keys_into_array(config: HeaderConfiguration): Array<string> {
        let output_array: Array<string> = [];
        for (let key in config) {
            output_array.push(key);
        }

        return output_array;
    }

    generate_signature_base_string(http_method: string, request_uri: string, parameter_string: string): string {
        const percent_encoded_uri: string = this.percent_encode_string(request_uri);
        const percent_encoded_parameter_string: string = this.percent_encode_string(parameter_string);

        return `${http_method}&${percent_encoded_uri}${percent_encoded_parameter_string}`;
    }

    generate_parameter_string(config: HeaderConfiguration): string {
        let parameter_list = [];
        const encoded_config_parameters = this.percent_encode_configuration_object(config);
        const config_key_list = this.flatten_configuration_keys_into_array(encoded_config_parameters);
        const sorted_config_key_list = this.sort_configuration_keys(config_key_list);

        for (let i in sorted_config_key_list) {
            const config_key = sorted_config_key_list[i];
            const config_value = encoded_config_parameters[config_key];

            if (config_value.length > 1) {
                parameter_list.push(`${config_key}=${config_value}`);
            }
        }

        return parameter_list.join('&');;
    }

    generate_signature(signing_key: string, signature_base_string: string): string {
        const signature = hmac(signing_key, signature_base_string);
        return signature;
    }

    build_authorization_header(is_regular_request: boolean): string {
        const
            consumer_secret = this.oauth_config.oauth_consumer_secret || '',
            token_secret = this.oauth_config.oauth_token_secret || '',
            parameter_string = this.generate_parameter_string({
                ...this.oauth_config,
                ...this.oauth_misc
            }),
            signature_base_string = this.generate_signature_base_string(
                this.http_method, this.request_uri, parameter_string
            ),
            signing_key = `${this.percent_encode_string(consumer_secret)}&${this.percent_encode_string(token_secret)}`,
            signature = this.generate_signature(signing_key, signature_base_string);

        let header_options: any = {
            oauth_callback: this.percent_encode_string(this.oauth_config.oauth_callback),
            oauth_consumer_key: this.percent_encode_string(this.oauth_config.oauth_consumer_key),
            oauth_nonce: this.percent_encode_string(this.generate_nonce()),
            oauth_signature: this.percent_encode_string(signature),
            oauth_signature_method: this.percent_encode_string(this.oauth_config.oauth_signature_method),
            oauth_timestamp: this.percent_encode_string(this.oauth_config.oauth_timestamp),
            oauth_token: this.percent_encode_string(this.oauth_config.oauth_token),
            oauth_version: this.percent_encode_string(this.oauth_config.oauth_version)
        };

        if (is_regular_request) {
            header_options = {
                ...header_options,
                oauth_token_secret: this.percent_encode_string(token_secret),
                oauth_consumer_secret: this.percent_encode_string(consumer_secret)
            }
        }

        let headers_list = [];
        for (let header in header_options) {
            if (header_options[header].length < 1) continue;
            headers_list.push(`${header}="${header_options[header]}"`);
        }

        return `Oauth ${headers_list.join(', ')}`;
    }
}

export default TwitterHelper;