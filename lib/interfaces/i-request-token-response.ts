/**
 * @author Oguntuberu Nathan O. <nateoguns.work@gmail.com>
**/

export default interface RequestTokenResponse {
    oauth_token?: string;
    oauth_token_secret?: string;
    oauth_callback_confirmed?: string;
}