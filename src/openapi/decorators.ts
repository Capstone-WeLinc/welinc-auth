import { applyDecorators } from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiCookieAuth,
  ApiExtraModels,
  ApiForbiddenResponse,
  ApiResponse,
  ApiSecurity,
  ApiUnauthorizedResponse,
  getSchemaPath,
} from '@nestjs/swagger';
import { SECURITY } from './document';
import { CodedError, OAuthError } from './schemas';

/**
 * VRMS spec 0026 decorators: the security scheme a route accepts (AC-8) and its error replies
 * (AC-4). Several scheme decorators on one route mean any one of them is accepted.
 */

/** A user access token as `Authorization: Bearer`. */
export const ApiUserToken = () => ApiBearerAuth(SECURITY.userToken);

/** A client credentials service token as `Authorization: Bearer`. */
export const ApiServiceToken = () => ApiBearerAuth(SECURITY.serviceToken);

/** welinc-auth's SSO cookie (the portal routes). */
export const ApiSsoCookie = () => ApiCookieAuth(SECURITY.ssoCookie);

/** The `vrms_rt` cookie on `/vrms/session` (backend-vrms only; kept here so both copies match). */
export const ApiVrmsSession = () => ApiCookieAuth(SECURITY.vrmsSession);

/** A `private_key_jwt` client assertion in the form body of `/auth/token`. */
export const ApiClientAssertion = () => ApiSecurity(SECURITY.clientAssertion);

/** `API_OPERATION` in @nestjs/swagger (its constants file is not exported). */
const API_OPERATION = 'swagger/apiOperation';

const COOKIE_ROUTE_NOTE =
  'Called by a web app with its cookie. A request sent from this docs page is refused by the ' +
  'Origin check (403 `CSRF_REJECTED`), so try it from the portal instead.';

/** The AC-8 line on every cookie route: the docs page can't call it. */
export const ApiCookieRoute = (): MethodDecorator => (_target, _key, d) => {
  // Merges only the description: ApiOperation would reset the summary the plugin reads from comments
  const previous = (Reflect.getMetadata(API_OPERATION, d.value!) ??
    {}) as Record<string, unknown>;
  Reflect.defineMetadata(
    API_OPERATION,
    { ...previous, description: COOKIE_ROUTE_NOTE },
    d.value!,
  );
  return d;
};

/** One error status with the `code` values the route can answer (contract 0001 sections 7 to 11). */
export function ApiErrors(status: number, codes: readonly string[]) {
  return applyDecorators(
    ApiExtraModels(CodedError),
    ApiResponse({
      status,
      description: codes.map((c) => `\`${c}\``).join(', '),
      schema: {
        allOf: [
          { $ref: getSchemaPath(CodedError) },
          { properties: { code: { type: 'string', enum: [...codes] } } },
        ],
      },
    }),
  );
}

/** `POST /auth/token`'s errors, in the OAuth shape: the `error` values per status. */
export function ApiOAuthErrors(status: number, errors: readonly string[]) {
  return applyDecorators(
    ApiExtraModels(OAuthError),
    ApiResponse({
      status,
      description: errors.map((e) => `\`${e}\``).join(', '),
      schema: {
        allOf: [
          { $ref: getSchemaPath(OAuthError) },
          { properties: { error: { type: 'string', enum: [...errors] } } },
        ],
      },
    }),
  );
}

/** The generic 400, 401 and 403 set, for routes outside the contract route index (AC-4). */
export const ApiGenericErrors = () =>
  applyDecorators(
    ApiBadRequestResponse({
      description: 'The input failed validation',
      type: CodedError,
    }),
    ApiUnauthorizedResponse({
      description: 'No valid credentials',
      type: CodedError,
    }),
    ApiForbiddenResponse({
      description: 'Not allowed for this caller',
      type: CodedError,
    }),
  );
