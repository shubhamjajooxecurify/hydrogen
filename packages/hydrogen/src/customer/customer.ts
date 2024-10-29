import type {GenericVariables} from '@shopify/hydrogen-codegen';
import type {WritableDeep} from 'type-fest';
import {
  DEFAULT_CUSTOMER_API_VERSION,
  CUSTOMER_ACCOUNT_SESSION_KEY,
  BUYER_SESSION_KEY,
  USER_AGENT,
} from './constants';
import {clearSession, redirect, logSubRequestEvent} from './auth.helpers';
import {
  minifyQuery,
  throwErrorWithGqlLink,
  type GraphQLErrorOptions,
  GraphQLError,
} from '../utils/graphql';
import {parseJSON} from '../utils/parse-json';
import {
  CrossRuntimeRequest,
  getHeader,
  getDebugHeaders,
} from '../utils/request';
import {getCallerStackLine, withSyncStack} from '../utils/callsites';
import {
  getRedirectUrl,
  ensureLocalRedirectUrl,
} from '../utils/get-redirect-url';
import type {
  CustomerAccountOptions,
  CustomerAPIResponse,
  LoginOptions,
  LogoutOptions,
  Buyer,
  CustomerAccount,
} from './types';
import {warnOnce} from '../utils/warning';

const DEFAULT_LOGIN_URL = '/account/login';
const DEFAULT_REDIRECT_PATH = '/account';

function defaultAuthStatusHandler(request: CrossRuntimeRequest) {
  if (!request.url) return DEFAULT_LOGIN_URL;

  const {pathname} = new URL(request.url);

  const redirectTo =
    DEFAULT_LOGIN_URL +
    `?${new URLSearchParams({return_to: pathname}).toString()}`;

  return redirect(redirectTo);
}

export function createCustomerAccountClient({
  session,
  customerAccountId,
  customerAccountUrl: deprecatedCustomerAccountUrl,
  shopId,
  storeDomain,
  customerApiVersion = DEFAULT_CUSTOMER_API_VERSION,
  request,
  waitUntil,
  authUrl,
  customAuthStatusHandler,
  logErrors = true,
  unstableB2b = false,
}: CustomerAccountOptions): CustomerAccount {
  if (customerApiVersion !== DEFAULT_CUSTOMER_API_VERSION) {
    console.warn(
      `[h2:warn:createCustomerAccountClient] You are using Customer Account API version ${customerApiVersion} when this version of Hydrogen was built for ${DEFAULT_CUSTOMER_API_VERSION}.`,
    );
  }

  if (!session) {
    console.warn(
      `[h2:warn:createCustomerAccountClient] session is required to use Customer Account API. Ensure the session object passed in exist.`,
    );
  }

  if (!request?.url) {
    throw new Error(
      '[h2:error:createCustomerAccountClient] The request object does not contain a URL.',
    );
  }

  if (!!deprecatedCustomerAccountUrl && !shopId) {
    warnOnce(
      '[h2:warn:createCustomerAccountClient] The `customerAccountUrl` option is deprecated and will be removed in a future version. Please remove `customerAccountUrl` and supply a `shopId: env.SHOP_ID` option instead.\n\nIf using `createHydrogenContext`, ensure there is a SHOP_ID defined in your local .env file.',
    );
  }

  const authStatusHandler = customAuthStatusHandler
    ? customAuthStatusHandler
    : () => defaultAuthStatusHandler(request);

  const requestUrl = new URL(request.url);
  const httpsOrigin =
    requestUrl.protocol === 'http:'
      ? requestUrl.origin.replace('http', 'https')
      : requestUrl.origin;

  const customerAccountApiUrl = `https://${storeDomain}/api/2024-04/graphql.json`;
  const adminApiApiUrl = `https://${storeDomain}/admin/api/2024-10/graphql.json`;

  async function fetchCustomerAPI<T>({
    query,
    type,
    variables = {},
  }: {
    query: string;
    type: 'query' | 'mutation';
    variables?: GenericVariables;
  }) {
    const accessToken = await getAccessToken();
    if (!accessToken) {
      throw authStatusHandler();
    }

    // Get stack trace before losing it with any async operation.
    // Since this is an internal function that is always called from
    // the public query/mutate wrappers, add 1 to the stack offset.
    const stackInfo = getCallerStackLine?.();

    const startTime = new Date().getTime();

    const response = await fetch(customerAccountApiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': USER_AGENT,
        Origin: httpsOrigin,
        'X-Shopify-Storefront-Access-Token': '996974149555cd92bc6c5f80ec1cf8ad',
      },
      body: JSON.stringify({query, variables}),
    });

    logSubRequestEvent?.({
      url: customerAccountApiUrl,
      startTime,
      response,
      waitUntil,
      stackInfo,
      query,
      variables,
      ...getDebugHeaders(request),
    });

    const body = await response.text();

    const errorOptions: GraphQLErrorOptions<T> = {
      url: customerAccountApiUrl,
      response,
      type,
      query,
      queryVariables: variables,
      errors: undefined,
      client: 'customer',
    };

    if (!response.ok) {
      if (response.status === 401) {
        // clear session because current access token is invalid
        clearSession(session);

        const authFailResponse = authStatusHandler();
        throw authFailResponse;
      }

      /**
       * The Customer API might return a string error, or a JSON-formatted {error: string}.
       * We try both and conform them to a single {errors} format.
       */
      let errors;
      try {
        errors = parseJSON(body);
      } catch (_e) {
        errors = [{message: body}];
      }

      throwErrorWithGqlLink({...errorOptions, errors});
    }

    try {
      const APIresponse = parseJSON(body) as CustomerAPIResponse<T>;
      const {errors} = APIresponse;

      const gqlErrors = errors?.map(
        ({message, ...rest}) =>
          new GraphQLError(message, {
            ...(rest as WritableDeep<typeof rest>),
            clientOperation: `customerAccount.${errorOptions.type}`,
            requestId: response.headers.get('x-request-id'),
            queryVariables: variables,
            query,
          }),
      );

      return {...APIresponse, ...(errors && {errors: gqlErrors})};
    } catch (e) {
      throwErrorWithGqlLink({...errorOptions, errors: [{message: body}]});
    }
  }

  async function fetchAdminAPI<T>({
    query,
    type,
    variables = {},
  }: {
    query: string;
    type: 'query' | 'mutation';
    variables?: GenericVariables;
  }) {
    const accessToken = await getAccessToken();
    if (!accessToken) {
      throw authStatusHandler();
    }

    // Get stack trace before losing it with any async operation.
    // Since this is an internal function that is always called from
    // the public query/mutate wrappers, add 1 to the stack offset.
    const stackInfo = getCallerStackLine?.();

    const startTime = new Date().getTime();

    const response = await fetch(adminApiApiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': USER_AGENT,
        Origin: httpsOrigin,
        'X-Shopify-Access-Token': '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',
      },
      body: JSON.stringify({query, variables}),
    });

    logSubRequestEvent?.({
      url: customerAccountApiUrl,
      startTime,
      response,
      waitUntil,
      stackInfo,
      query,
      variables,
      ...getDebugHeaders(request),
    });

    const body = await response.text();

    const errorOptions: GraphQLErrorOptions<T> = {
      url: customerAccountApiUrl,
      response,
      type,
      query,
      queryVariables: variables,
      errors: undefined,
      client: 'customer',
    };

    if (!response.ok) {
      if (response.status === 401) {
        // clear session because current access token is invalid
        clearSession(session);

        const authFailResponse = authStatusHandler();
        throw authFailResponse;
      }

      /**
       * The Customer API might return a string error, or a JSON-formatted {error: string}.
       * We try both and conform them to a single {errors} format.
       */
      let errors;
      try {
        errors = parseJSON(body);
      } catch (_e) {
        errors = [{message: body}];
      }

      throwErrorWithGqlLink({...errorOptions, errors});
    }

    try {
      const APIresponse = parseJSON(body) as CustomerAPIResponse<T>;
      const {errors} = APIresponse;

      const gqlErrors = errors?.map(
        ({message, ...rest}) =>
          new GraphQLError(message, {
            ...(rest as WritableDeep<typeof rest>),
            clientOperation: `customerAccount.${errorOptions.type}`,
            requestId: response.headers.get('x-request-id'),
            queryVariables: variables,
            query,
          }),
      );

      return {...APIresponse, ...(errors && {errors: gqlErrors})};
    } catch (e) {
      throwErrorWithGqlLink({...errorOptions, errors: [{message: body}]});
    }
  }

  async function isLoggedIn() {
    if (!shopId && (!deprecatedCustomerAccountUrl || !customerAccountId))
      return false;

    const customerAccount = session.get(CUSTOMER_ACCOUNT_SESSION_KEY);
    const accessToken = customerAccount?.accessToken;

    if (!accessToken) return false;

    return true;
  }

  async function handleAuthStatus() {
    if (!(await isLoggedIn())) {
      throw authStatusHandler();
    }
  }

  async function getAccessToken() {
    const hasAccessToken = await isLoggedIn();

    if (hasAccessToken)
      return session.get(CUSTOMER_ACCOUNT_SESSION_KEY)?.accessToken;
  }

  async function mutate(
    mutation: Parameters<CustomerAccount['mutate']>[0],
    options?: Parameters<CustomerAccount['mutate']>[1],
  ) {
    mutation = minifyQuery(mutation);

    options = {
      variables: {
        ...options?.variables,
        customerAccessToken: session.get(CUSTOMER_ACCOUNT_SESSION_KEY)
          ?.accessToken,
      },
    };

    return withSyncStack(
      fetchCustomerAPI({query: mutation, type: 'mutation', ...options}),
      {logErrors},
    );
  }

  async function query(
    query: Parameters<CustomerAccount['query']>[0],
    options?: Parameters<CustomerAccount['query']>[1],
  ) {
    query = minifyQuery(query);

    options = {
      variables: {
        ...options?.variables,
        customerAccessToken: session.get(CUSTOMER_ACCOUNT_SESSION_KEY)
          ?.accessToken,
      },
    };

    if (options?.variables?.orderId) {
      return withSyncStack(fetchAdminAPI({query, type: 'query', ...options}), {
        logErrors,
      });
    }

    return withSyncStack(fetchCustomerAPI({query, type: 'query', ...options}), {
      logErrors,
    });
  }

  function setBuyer(buyer: Buyer) {
    session.set(BUYER_SESSION_KEY, {
      ...session.get(BUYER_SESSION_KEY),
      ...buyer,
    });
  }

  async function getBuyer() {
    // check loggedIn and trigger refresh if expire
    const hasAccessToken = await isLoggedIn();

    if (!hasAccessToken) {
      return;
    }

    return session.get(BUYER_SESSION_KEY);
  }

  return {
    login: async (options?: LoginOptions) => {
      const loginUrl = new URL(
        `https://local.miniorange.in/moas/broker/login/shopify/${storeDomain}/index`,
      );

      session.set(CUSTOMER_ACCOUNT_SESSION_KEY, {
        ...session.get(CUSTOMER_ACCOUNT_SESSION_KEY),
        redirectPath:
          getRedirectUrl(request.url) ||
          getHeader(request, 'Referer') ||
          DEFAULT_REDIRECT_PATH,
      });

      return redirect(loginUrl.toString());
    },

    logout: async (options?: LogoutOptions) => {
      const postLogoutRedirectUri = ensureLocalRedirectUrl({
        requestUrl: httpsOrigin,
        defaultUrl: httpsOrigin,
        redirectUrl: options?.postLogoutRedirectUri,
      });

      const logoutUrl = postLogoutRedirectUri;

      clearSession(session);

      return redirect(logoutUrl);
    },
    isLoggedIn,
    handleAuthStatus,
    getAccessToken,
    getApiUrl: () => customerAccountApiUrl,
    mutate: mutate as CustomerAccount['mutate'],
    query: query as CustomerAccount['query'],
    authorize: async () => {
      session.set(CUSTOMER_ACCOUNT_SESSION_KEY, {
        accessToken: requestUrl.searchParams.get('token')?.toString(),
      });

      return redirect(DEFAULT_REDIRECT_PATH);
    },
    UNSTABLE_setBuyer: setBuyer,
    UNSTABLE_getBuyer: getBuyer,
  };
}
