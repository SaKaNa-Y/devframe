import type { DevframeNodeContext, DevframeNodeRpcSession } from 'devframe/types'
import type { ColorFn } from 'devframe/utils/colors'
import type { DevframeAuthHandler } from '../node/auth'
import { colors } from 'devframe/utils/colors'
import { s } from 'devframe/utils/simple-schema'
import { DEVFRAME_AUTH_TOKEN_QUERY_PARAM, isAnonymousRpcMethod } from '../constants'
import { buildOtpAuthUrl, exchangeTempAuthCode, getTempAuthCode, verifyAuthToken } from '../node/auth/state'
import { getInternalContext } from '../node/hub-internals/context'
import { defineRpcFunction } from '../rpc/define'

export interface CreateInteractiveAuthOptions {
  /**
   * Static, pre-shared bearer tokens that are always trusted, for CI runs
   * or shared machines where the interactive code prompt would only get in
   * the way. Checked in both the handshake handler and the connect-time
   * hook, alongside tokens minted by a real code exchange.
   */
  clientAuthTokens?: string[]
  /**
   * Print the current code + magic-link URL. Devframe stays headless, so
   * there is no default banner printed automatically; call
   * `auth.printBanner()` yourself once the server is listening. Defaults to
   * {@link createAuthBanner}'s output; pass its result here directly to
   * rebrand the box (title / colors), or your own function to replace the
   * format outright.
   */
  banner?: AuthBannerFunction
  /**
   * Called once a code exchange succeeds, so a host rendering its own
   * banner can retract it. Fires after the rotated code is printed, so
   * such a host drops that follow-up too and calls `auth.printBanner()`
   * when it next wants a code on screen. Connect-time trust from a static
   * or remote-dock token doesn't call this.
   */
  onTrusted?: (info: { session: DevframeNodeRpcSession, authToken: string }) => void
  /**
   * The base URL the magic link should point at. Defaults to
   * `context.host.resolveOrigin()`.
   */
  serverUrl?: () => string
}

/** Signature of `options.banner`: render the current auth code + magic-link URL. */
export type AuthBannerFunction = (info: { code: string, url: string }) => void

/** Palette for {@link createAuthBanner}'s box - one color per part, so a host can rebrand a subset. */
export interface CreateAuthBannerColorsOptions {
  border: ColorFn
  title: ColorFn
  label: ColorFn
  code: ColorFn
  url: ColorFn
}

export interface CreateAuthBannerOptions {
  /** Box title. Defaults to `'Devframe'` - set to your product name for branding. */
  title?: string
  /** Palette overrides; unset colors fall back to dim/bold/cyan defaults. */
  colors?: Partial<CreateAuthBannerColorsOptions>
}

/**
 * Build a {@link AuthBannerFunction} that renders the auth code + magic-link
 * URL as a small bordered box, its two rows label-aligned. `createInteractiveAuth`
 * falls back to `createAuthBanner()` when no `banner` is given; call this
 * yourself to rebrand the box (`title` / `colors`) and pass the result as
 * `options.banner`.
 */
export function createAuthBanner(options: CreateAuthBannerOptions = {}): AuthBannerFunction {
  const title = options.title ?? 'Devframe'
  const palette: CreateAuthBannerColorsOptions = {
    border: colors.dim,
    title: colors.bold,
    label: colors.dim,
    code: colors.bold,
    url: colors.cyan,
    ...options.colors,
  }

  return (info) => {
    const rows: [label: string, value: string, color: ColorFn][] = [
      ['auth code', info.code, palette.code],
      ['or open', info.url, palette.url],
    ]
    const labelWidth = Math.max(...rows.map(([label]) => label.length))
    const contentWidth = Math.max(...rows.map(([, value]) => labelWidth + 2 + value.length))
    const titleBarLength = title.length + 3
    const lineWidth = Math.max(contentWidth, titleBarLength - 2)

    const top = [
      palette.border(`╭─`),
      palette.title(title),
      palette.border(`${'─'.repeat(Math.max(lineWidth + 2 - titleBarLength, 0))}╮`),
    ].join(' ')
    const bottom = `╰${'─'.repeat(lineWidth + 2)}╯`
    const body = rows.map(([label, value, color]) => {
      const plain = `${label.padEnd(labelWidth)}  ${value}`
      const pad = ' '.repeat(lineWidth - plain.length)
      return `${palette.border('│')} ${palette.label(label.padEnd(labelWidth))}  ${color(value)}${pad} ${palette.border('│')}`
    })

    // eslint-disable-next-line no-console
    console.log(`\n${palette.border(top)}\n${body.join('\n')}\n${palette.border(bottom)}\n`)
  }
}

/**
 * Package the interactive OTP auth protocol devframe's primitives
 * (`exchangeTempAuthCode`, `verifyAuthToken`, `revokeAuthToken`,
 * `getTempAuthCode`, `buildOtpAuthUrl`) implement into a ready-made
 * {@link DevframeAuthHandler}: the handshake RPC functions, the resolver
 * gate, the connect-time trust hook, and the startup banner.
 *
 * The auth storage stays internal to this handler; callers never reach into
 * `devframe/node/hub-internals` themselves.
 *
 * ```ts
 * import { createInteractiveAuth } from 'devframe/recipes/interactive-auth'
 *
 * const auth = createInteractiveAuth(ctx)
 * auth.rpcFunctions.forEach(fn => ctx.rpc.register(fn))
 * auth.printBanner()
 *
 * // wire `auth.authorize` / `auth.onConnect` into your transport, or pass
 * // the whole handler to `initDevframe` / `initHub` via their `auth` option.
 * ```
 */
export function createInteractiveAuth(
  context: DevframeNodeContext,
  options: CreateInteractiveAuthOptions = {},
): DevframeAuthHandler {
  const internal = getInternalContext(context)
  const storage = internal.storage.auth
  const staticTokens = new Set(options.clientAuthTokens ?? [])

  function isStaticToken(token: string | undefined): boolean {
    return !!token && staticTokens.has(token)
  }

  function resolveServerUrl(): string {
    return options.serverUrl?.() ?? context.host.resolveOrigin()
  }

  const banner = options.banner ?? createAuthBanner()

  let bannerPrintedForCode: string | undefined
  function printBanner(): void {
    const code = getTempAuthCode()
    if (code === bannerPrintedForCode)
      return
    bannerPrintedForCode = code
    const url = buildOtpAuthUrl(resolveServerUrl(), code)
    banner({ code, url })
  }

  const anonymousAuth = defineRpcFunction({
    name: 'anonymous:devframe:auth',
    type: 'action',
    jsonSerializable: true,
    args: [s.object({
      authToken: s.string(),
      ua: s.string(),
      origin: s.string(),
    })],
    returns: s.object({ isTrusted: s.boolean() }),
    handler(params) {
      const session = context.rpc.getCurrentRpcSession()
      if (!session)
        return { isTrusted: false }
      if (session.meta.isTrusted)
        return { isTrusted: true }
      if (isStaticToken(params.authToken)) {
        session.meta.clientAuthToken = params.authToken
        session.meta.isTrusted = true
        return { isTrusted: true }
      }
      return { isTrusted: verifyAuthToken(params.authToken, session, storage) }
    },
  })

  const anonymousAuthExchange = defineRpcFunction({
    name: 'anonymous:devframe:auth:exchange',
    type: 'action',
    jsonSerializable: true,
    args: [s.object({
      code: s.string(),
      ua: s.string(),
      origin: s.string(),
    })],
    returns: s.object({ authToken: s.nullable(s.string()) }),
    handler(params) {
      const session = context.rpc.getCurrentRpcSession()
      if (!session)
        return { authToken: null }
      const authToken = exchangeTempAuthCode(params.code, session, params, storage)
      // The code was just consumed (success or a rotating failure); the
      // next `printBanner()` call shows whatever code is current now.
      printBanner()
      if (authToken)
        options.onTrusted?.({ session, authToken })
      return { authToken }
    },
  })

  const revoke = defineRpcFunction({
    name: 'devframe:auth:revoke',
    type: 'action',
    jsonSerializable: true,
    args: [],
    returns: s.void(),
    async handler() {
      const session = context.rpc.getCurrentRpcSession()
      const token = session?.meta.clientAuthToken
      if (token)
        await internal.revokeAuthToken(token)
    },
  })

  function authorize(methodName: string, session: DevframeNodeRpcSession): boolean {
    if (isAnonymousRpcMethod(methodName))
      return true
    return !!session.meta.isTrusted
  }

  function onConnect(
    connection: { request?: { url?: string, headers?: { get?: (name: string) => string | null | undefined } } },
    session: DevframeNodeRpcSession,
  ): void {
    let token: string | undefined
    let requestOrigin: string | undefined
    try {
      const url = new URL(connection.request?.url ?? '', 'http://localhost')
      token = url.searchParams.get(DEVFRAME_AUTH_TOKEN_QUERY_PARAM) ?? undefined
    }
    catch {}
    try {
      requestOrigin = connection.request?.headers?.get?.('origin') ?? undefined
    }
    catch {}
    if (!token)
      return
    if (isStaticToken(token)) {
      session.meta.clientAuthToken = token
      session.meta.isTrusted = true
      return
    }
    // A persisted bearer minted by the code exchange (returning browser).
    if (verifyAuthToken(token, session, storage))
      return
    // A session-only remote-UI dock token (see `allocateRemoteToken`). These
    // never enter the persisted store, so `verifyAuthToken` can't see them;
    // check them here so a remote dock's iframe actually authenticates, and so
    // `originLock` binds the token to the dock's recorded origin.
    if (internal.isRemoteTokenTrusted(token, requestOrigin)) {
      session.meta.clientAuthToken = token
      session.meta.isTrusted = true
    }
  }

  function buildOpenUrl(url: string): string {
    return buildOtpAuthUrl(url)
  }

  return {
    rpcFunctions: [anonymousAuth, anonymousAuthExchange, revoke],
    authorize,
    onConnect: onConnect as DevframeAuthHandler['onConnect'],
    printBanner,
    buildOpenUrl,
  }
}
