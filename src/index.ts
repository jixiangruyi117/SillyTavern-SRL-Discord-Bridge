interface Env {
  DB: D1Database
  DISCORD_APPLICATION_ID: string
  DISCORD_PUBLIC_KEY: string
  DISCORD_BOT_TOKEN: string
  HANDOFF_TTL_SECONDS?: string
  SRL_WEB_URL?: string
}

interface DiscordInteraction {
  type: number
  guild_id?: string
  channel_id?: string
  channel?: Record<string, unknown>
  data?: {
    type?: number
    target_id?: string
    resolved?: {
      messages?: Record<string, Record<string, unknown>>
    }
  }
}

const COMMAND_NAME = '保存到资源库'
const THREAD_CHANNEL_TYPES = new Set([10, 11, 12])
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
}

function json(value: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers)
  headers.set('Content-Type', 'application/json; charset=utf-8')
  for (const [key, item] of Object.entries(CORS_HEADERS)) headers.set(key, item)
  return new Response(JSON.stringify(value), { ...init, headers })
}

function html(value: string, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers)
  headers.set('Content-Type', 'text/html; charset=utf-8')
  return new Response(value, { ...init, headers })
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/gu,
    (character) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character] ??
      character,
  )
}

function hexToBytes(value: string): Uint8Array<ArrayBuffer> {
  if (!/^[0-9a-f]+$/iu.test(value) || value.length % 2 !== 0) throw new Error('invalid hex')
  const bytes = new Uint8Array(value.length / 2)
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/gu, '')
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return bytesToHex(new Uint8Array(digest))
}

async function verifyDiscordRequest(request: Request, rawBody: string, publicKeyHex: string) {
  const signature = request.headers.get('X-Signature-Ed25519')
  const timestamp = request.headers.get('X-Signature-Timestamp')
  if (!signature || !timestamp) return false
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      hexToBytes(publicKeyHex.trim()),
      { name: 'Ed25519' },
      false,
      ['verify'],
    )
    const message = new TextEncoder().encode(`${timestamp}${rawBody}`)
    return crypto.subtle.verify('Ed25519', key, hexToBytes(signature), message)
  } catch {
    return false
  }
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function readForumTags(channel?: Record<string, unknown>): string[] {
  if (!channel) return []
  const applied = Array.isArray(channel.applied_tags)
    ? channel.applied_tags.filter((value): value is string => typeof value === 'string')
    : []
  const available = Array.isArray(channel.available_tags)
    ? channel.available_tags.flatMap((value) => {
        const tag = asRecord(value)
        const id = asString(tag?.id)
        const name = asString(tag?.name)
        return id && name ? [{ id, name }] : []
      })
    : []
  const names = new Map(available.map((tag) => [tag.id, tag.name]))
  return applied.flatMap((id) => {
    const name = names.get(id)
    return name ? [name] : []
  })
}

function normalizeAttachments(value: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) return []
  return value.flatMap((item) => {
    const attachment = asRecord(item)
    if (!attachment) return []
    const id = asString(attachment.id)
    const name = asString(attachment.filename)
    const url = asString(attachment.url)
    if (!id || !name || !url) return []
    return [
      {
        id,
        name,
        size: asNumber(attachment.size) ?? 0,
        url,
        ...(asString(attachment.proxy_url) ? { proxyUrl: asString(attachment.proxy_url) } : {}),
        ...(asString(attachment.content_type)
          ? { contentType: asString(attachment.content_type) }
          : {}),
        ...(asNumber(attachment.width) !== undefined ? { width: asNumber(attachment.width) } : {}),
        ...(asNumber(attachment.height) !== undefined
          ? { height: asNumber(attachment.height) }
          : {}),
      },
    ]
  })
}

function buildCapture(interaction: DiscordInteraction): Record<string, unknown> {
  const channelId = interaction.channel_id ?? ''
  const targetId = interaction.data?.target_id ?? ''
  const message = interaction.data?.resolved?.messages?.[targetId]
  if (!channelId || !targetId || !message) throw new Error('Discord 没有提供被选中的消息')

  const author = asRecord(message.author)
  const authorId = asString(author?.id)
  const authorName =
    asString(author?.global_name) || asString(author?.username) || asString(message.author_name)
  if (!authorId || !authorName) throw new Error('无法读取消息作者')

  const channel = interaction.channel
  const channelType = asNumber(channel?.type)
  const threadId =
    channelType !== undefined && THREAD_CHANNEL_TYPES.has(channelType) ? channelId : undefined
  const starterMessageId = threadId ?? targetId
  const isStarter = targetId === starterMessageId
  const guildPath = interaction.guild_id ?? '@me'
  const canonicalUrl = `https://discord.com/channels/${encodeURIComponent(guildPath)}/${encodeURIComponent(channelId)}/${encodeURIComponent(targetId)}`

  return {
    ...(interaction.guild_id ? { guildId: interaction.guild_id } : {}),
    channelId,
    ...(threadId ? { threadId } : {}),
    starterMessageId,
    isStarter,
    messageId: targetId,
    canonicalUrl,
    authorId,
    authorName,
    content: typeof message.content === 'string' ? message.content : '',
    timestamp: asString(message.timestamp) || new Date().toISOString(),
    ...(asString(message.edited_timestamp)
      ? { editedTimestamp: asString(message.edited_timestamp) }
      : {}),
    ...(threadId && asString(channel?.name) ? { title: asString(channel?.name) } : {}),
    forumTags: readForumTags(channel),
    embeds: Array.isArray(message.embeds)
      ? message.embeds.filter((value) => Boolean(asRecord(value)))
      : [],
    attachments: normalizeAttachments(message.attachments),
  }
}

function handoffTtlSeconds(env: Env): number {
  const configured = Number(env.HANDOFF_TTL_SECONDS)
  return Number.isFinite(configured)
    ? Math.min(1_800, Math.max(300, Math.round(configured)))
    : 1_200
}

async function cleanupExpired(env: Env): Promise<void> {
  const now = Date.now()
  await env.DB.prepare(
    'DELETE FROM handoffs WHERE expires_at <= ? OR (consumed_at IS NOT NULL AND consumed_at <= ?)',
  )
    .bind(now, now - 60_000)
    .run()
}

async function createHandoff(env: Env, payload: unknown): Promise<string> {
  const token = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)))
  const tokenHash = await sha256Hex(token)
  const now = Date.now()
  await env.DB.prepare(
    'INSERT INTO handoffs (token_hash, payload, created_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, NULL)',
  )
    .bind(tokenHash, JSON.stringify(payload), now, now + handoffTtlSeconds(env) * 1_000)
    .run()
  return token
}

async function consumeHandoff(env: Env, token: string): Promise<Response> {
  if (!/^[A-Za-z0-9_-]{30,160}$/u.test(token))
    return json({ error: 'invalid_token' }, { status: 400 })
  const tokenHash = await sha256Hex(token)
  const now = Date.now()
  const row = await env.DB.prepare(
    'SELECT payload FROM handoffs WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ? LIMIT 1',
  )
    .bind(tokenHash, now)
    .first<{ payload: string }>()
  if (!row) return json({ error: 'handoff_not_found_or_expired' }, { status: 404 })

  const claimed = await env.DB.prepare(
    'UPDATE handoffs SET consumed_at = ? WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?',
  )
    .bind(now, tokenHash, now)
    .run()
  if ((claimed.meta.changes ?? 0) !== 1)
    return json({ error: 'handoff_already_consumed' }, { status: 409 })

  try {
    return json({ capture: JSON.parse(row.payload) })
  } catch {
    return json({ error: 'handoff_payload_invalid' }, { status: 500 })
  }
}

async function registerMessageCommand(env: Env): Promise<void> {
  if (!env.DISCORD_APPLICATION_ID || !env.DISCORD_BOT_TOKEN) {
    throw new Error('Discord Application ID / Bot Token 未配置')
  }
  const response = await fetch(
    `https://discord.com/api/v10/applications/${encodeURIComponent(env.DISCORD_APPLICATION_ID)}/commands`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bot ${env.DISCORD_BOT_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: COMMAND_NAME,
        type: 3,
        integration_types: [1],
        contexts: [0, 1, 2],
      }),
    },
  )
  if (!response.ok) {
    const detail = (await response.text()).slice(0, 800)
    throw new Error(`Discord command registration failed: ${response.status} ${detail}`)
  }
}

function authorizedSetup(request: Request, env: Env): boolean {
  const header = request.headers.get('Authorization') ?? ''
  return Boolean(env.DISCORD_BOT_TOKEN) && header === `Bearer ${env.DISCORD_BOT_TOKEN}`
}

function openPage(request: Request, env: Env, token: string): Response {
  if (!/^[A-Za-z0-9_-]{30,160}$/u.test(token)) return html('<h1>链接无效</h1>', { status: 400 })
  const origin = new URL(request.url).origin
  const nativeUrl = `srl://discord-source?worker=${encodeURIComponent(origin)}&token=${encodeURIComponent(token)}`
  let webUrl = ''
  if (env.SRL_WEB_URL) {
    try {
      const parsed = new URL(env.SRL_WEB_URL)
      parsed.searchParams.set('discordWorker', origin)
      parsed.searchParams.set('discordHandoff', token)
      webUrl = parsed.toString()
    } catch {
      webUrl = ''
    }
  }
  return html(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>打开 SRL</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:0 auto;padding:32px 20px;color:#173641;background:#f5fafb}h1{font-size:1.35rem}p{color:#647b83;line-height:1.65}.a{display:block;margin-top:12px;padding:12px 14px;border:1px solid #bfd0d4;border-radius:8px;color:#315e6d;text-decoration:none;font-weight:700}.hint{font-size:.82rem;color:#82949b}</style></head>
<body><h1>Discord 来源已接收</h1><p>消息正在你自己的 Worker 中临时等待领取。打开 SRL 后会写入本机资源库。</p>
<a class="a" href="${escapeHtml(nativeUrl)}">打开 SRL Android App</a>
${webUrl ? `<a class="a" href="${escapeHtml(webUrl)}">打开 SRL 网页 / PWA</a>` : ''}
<p class="hint">如果没有自动打开，请回到 SRL 的来源配置页继续领取。这个临时链接会自动过期。</p></body></html>`)
}

async function handleInteraction(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const rawBody = await request.text()
  if (!(await verifyDiscordRequest(request, rawBody, env.DISCORD_PUBLIC_KEY))) {
    return new Response('invalid request signature', { status: 401 })
  }

  let interaction: DiscordInteraction
  try {
    interaction = JSON.parse(rawBody) as DiscordInteraction
  } catch {
    return new Response('invalid json', { status: 400 })
  }

  if (interaction.type === 1) {
    return json({ type: 1 })
  }

  if (interaction.type !== 2 || interaction.data?.type !== 3) {
    return json({
      type: 4,
      data: { content: '这个命令只用于保存 Discord 消息。', flags: 64 },
    })
  }

  try {
    const capture = buildCapture(interaction)
    const token = await createHandoff(env, capture)
    const openUrl = `${new URL(request.url).origin}/open/${encodeURIComponent(token)}`
    ctx.waitUntil(cleanupExpired(env).catch((error) => console.error(error)))
    return json({
      type: 4,
      data: {
        content: '已完整接收这条消息。打开资源库后再选择关联到哪个资源。',
        flags: 64,
        components: [
          {
            type: 1,
            components: [{ type: 2, style: 5, label: '打开资源库', url: openUrl }],
          },
        ],
      },
    })
  } catch (error) {
    console.error(error)
    return json({
      type: 4,
      data: {
        content: `保存失败：${error instanceof Error ? error.message : '无法读取消息'}`,
        flags: 64,
      },
    })
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url)
    if (request.method === 'OPTIONS')
      return new Response(null, { status: 204, headers: CORS_HEADERS })

    if (url.pathname === '/health' && request.method === 'GET') {
      try {
        await env.DB.prepare('SELECT 1').first()
        return json({
          ok: true,
          database: true,
          discordConfigured: Boolean(
            env.DISCORD_APPLICATION_ID && env.DISCORD_PUBLIC_KEY && env.DISCORD_BOT_TOKEN,
          ),
          applicationId: env.DISCORD_APPLICATION_ID || null,
          commandName: COMMAND_NAME,
        })
      } catch {
        return json({ ok: false, database: false }, { status: 503 })
      }
    }

    if (url.pathname === '/setup/register' && request.method === 'POST') {
      if (!authorizedSetup(request, env)) return json({ error: 'unauthorized' }, { status: 401 })
      try {
        await registerMessageCommand(env)
        return json({ ok: true, commandName: COMMAND_NAME })
      } catch (error) {
        return json(
          { error: error instanceof Error ? error.message : 'command_registration_failed' },
          { status: 502 },
        )
      }
    }

    if (url.pathname === '/interactions' && request.method === 'POST') {
      return handleInteraction(request, env, ctx)
    }

    if (url.pathname.startsWith('/handoff/') && request.method === 'GET') {
      const token = decodeURIComponent(url.pathname.slice('/handoff/'.length))
      const response = await consumeHandoff(env, token)
      ctx.waitUntil(cleanupExpired(env).catch((error) => console.error(error)))
      return response
    }

    if (url.pathname.startsWith('/open/') && request.method === 'GET') {
      return openPage(request, env, decodeURIComponent(url.pathname.slice('/open/'.length)))
    }

    if (url.pathname === '/' && request.method === 'GET') {
      return html(
        `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SRL Discord Bridge</title></head><body style="font-family:system-ui,sans-serif;max-width:680px;margin:40px auto;padding:0 20px;color:#173641"><h1>SRL Discord Bridge</h1><p>这个 Worker 只负责 Discord 消息的短期 handoff，不是资源永久仓库。</p><p>Interactions Endpoint URL：</p><code style="overflow-wrap:anywhere">${escapeHtml(`${url.origin}/interactions`)}</code></body></html>`,
      )
    }

    return json({ error: 'not_found' }, { status: 404 })
  },
}
