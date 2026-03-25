import { Hono } from 'hono'
import type { Env } from '../[[route]]'

export const headersCheckRoute = new Hono<{ Bindings: Env }>()

interface HeaderCheck {
  name: string
  present: boolean
  value?: string
  recommendation: string
  severity: 'high' | 'medium' | 'low'
  pass: boolean
  scoreModifier: number
  result: string
}

interface HeadersResult {
  url: string
  headers: HeaderCheck[]
  score: number
  grade: string
  warnings: string[]
  source: string
  testsFailed: number
  testsPassed: number
  testsQuantity: number
}

interface MozillaScanResult {
  end_time: string
  grade: string
  hidden: boolean
  response_headers: Record<string, string>
  scan_id: number
  score: number
  likelihood_indicator: string
  start_time: string
  state: string
  tests_failed: number
  tests_passed: number
  tests_quantity: number
}

interface MozillaTestResult {
  expectation: string
  name: string
  output: {
    data?: unknown
    [key: string]: unknown
  }
  pass: boolean
  result: string
  score_description: string
  score_modifier: number
}

const HEADER_DISPLAY_NAMES: Record<string, string> = {
  'content-security-policy': 'Content-Security-Policy',
  'strict-transport-security': 'Strict-Transport-Security',
  'x-content-type-options': 'X-Content-Type-Options',
  'x-frame-options': 'X-Frame-Options',
  'x-xss-protection': 'X-XSS-Protection',
  'referrer-policy': 'Referrer-Policy',
  'permissions-policy': 'Permissions-Policy',
  'cross-origin-opener-policy': 'Cross-Origin-Opener-Policy',
  'cross-origin-resource-policy': 'Cross-Origin-Resource-Policy',
  'cross-origin-embedder-policy': 'Cross-Origin-Embedder-Policy',
}

const HEADER_RECOMMENDATIONS: Record<string, string> = {
  'content-security-policy': '设置CSP限制资源加载来源，防止XSS攻击',
  'strict-transport-security': '启用HSTS强制HTTPS连接，建议设置max-age至少31536000秒',
  'x-content-type-options': '设置为nosniff防止MIME类型嗅探',
  'x-frame-options': '设置为DENY或SAMEORIGIN防止点击劫持',
  'x-xss-protection': '设置为1; mode=block启用XSS过滤器（现代浏览器中CSP更有效）',
  'referrer-policy': '设置为strict-origin-when-cross-origin控制Referrer信息',
  'permissions-policy': '限制浏览器功能访问（摄像头、麦克风、地理位置等）',
  'cross-origin-opener-policy': '设置为same-origin防止跨源信息泄露',
  'cross-origin-resource-policy': '设置为same-origin防止跨源资源加载',
  'cross-origin-embedder-policy': '设置为require-corp增强跨源隔离',
}

const HEADER_SEVERITY: Record<string, 'high' | 'medium' | 'low'> = {
  'content-security-policy': 'high',
  'strict-transport-security': 'high',
  'x-content-type-options': 'medium',
  'x-frame-options': 'medium',
  'x-xss-protection': 'low',
  'referrer-policy': 'low',
  'permissions-policy': 'medium',
  'cross-origin-opener-policy': 'medium',
  'cross-origin-resource-policy': 'medium',
  'cross-origin-embedder-policy': 'low',
}

headersCheckRoute.get('/', async (c) => {
  const url = c.req.query('url')

  if (!url) {
    return c.json({ error: 'url is required' }, 400)
  }

  let cleanUrl = url.trim().toLowerCase()
  if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
    cleanUrl = 'https://' + cleanUrl
  }

  try {
    new URL(cleanUrl)
  } catch {
    return c.json({ error: 'Invalid URL' }, 400)
  }

  const urlObj = new URL(cleanUrl)
  const hostname = urlObj.hostname

  const cacheKey = `cache:headers:${cleanUrl}`
  try {
    const cached = await c.env.CACHE.get(cacheKey)
    if (cached) {
      return c.json({ ...JSON.parse(cached), cached: true })
    }
  } catch {}

  try {
    let scanResult: MozillaScanResult | null = null
    let testResults: Record<string, MozillaTestResult> | null = null

    try {
      const analyzeRes = await fetch(
        `https://http-observatory.security.mozilla.org/api/v1/analyze?host=${encodeURIComponent(hostname)}`,
        {
          method: 'POST',
          headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'rescan=true',
        }
      )

      if (analyzeRes.ok) {
        scanResult = (await analyzeRes.json()) as MozillaScanResult

        if (scanResult.state !== 'FINISHED') {
          let attempts = 0
          const maxAttempts = 10

          while (scanResult.state !== 'FINISHED' && attempts < maxAttempts) {
            await new Promise(resolve => setTimeout(resolve, 2000))
            const statusRes = await fetch(
              `https://http-observatory.security.mozilla.org/api/v1/analyze?host=${encodeURIComponent(hostname)}`
            )
            if (statusRes.ok) {
              scanResult = (await statusRes.json()) as MozillaScanResult
            }
            attempts++
          }
        }

        if (scanResult.state === 'FINISHED' && scanResult.scan_id) {
          const testsRes = await fetch(
            `https://http-observatory.security.mozilla.org/api/v1/getScanResults?scan=${scanResult.scan_id}`
          )
          if (testsRes.ok) {
            testResults = (await testsRes.json()) as Record<string, MozillaTestResult>
          }
        }
      }
    } catch (mozillaError) {
      console.log('Mozilla Observatory API failed:', mozillaError)
    }

    const warnings: string[] = []
    const headers: HeaderCheck[] = []

    if (testResults) {
      const headerTests = [
        'content-security-policy',
        'strict-transport-security',
        'x-content-type-options',
        'x-frame-options',
        'x-xss-protection',
        'referrer-policy',
        'permissions-policy',
        'cross-origin-opener-policy',
        'cross-origin-resource-policy',
        'cross-origin-embedder-policy',
      ]

      for (const testName of headerTests) {
        const test = testResults[testName]
        if (test) {
          const headerValue = scanResult?.response_headers?.[testName] || 
                             scanResult?.response_headers?.[HEADER_DISPLAY_NAMES[testName]]

          headers.push({
            name: HEADER_DISPLAY_NAMES[testName] || testName,
            present: !!headerValue || test.result.includes('implemented'),
            value: typeof test.output.data === 'string' ? test.output.data : headerValue || undefined,
            recommendation: HEADER_RECOMMENDATIONS[testName] || test.score_description,
            severity: HEADER_SEVERITY[testName] || 'medium',
            pass: test.pass,
            scoreModifier: test.score_modifier,
            result: test.result,
          })

          if (!test.pass && test.score_modifier < 0) {
            warnings.push(`${HEADER_DISPLAY_NAMES[testName]}: ${test.score_description}`)
          }
        }
      }
    } else {
      const res = await fetch(cleanUrl, {
        method: 'GET',
        redirect: 'follow',
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
      })

      const allHeaders: Record<string, string> = {}
      res.headers.forEach((value, key) => {
        allHeaders[key.toLowerCase()] = value
      })

      const headerNames = [
        'strict-transport-security',
        'content-security-policy',
        'x-content-type-options',
        'x-frame-options',
        'x-xss-protection',
        'referrer-policy',
        'permissions-policy',
        'cross-origin-opener-policy',
        'cross-origin-resource-policy',
        'cross-origin-embedder-policy',
      ]

      for (const headerName of headerNames) {
        const headerValue = allHeaders[headerName]
        headers.push({
          name: HEADER_DISPLAY_NAMES[headerName] || headerName,
          present: !!headerValue,
          value: headerValue || undefined,
          recommendation: HEADER_RECOMMENDATIONS[headerName] || '',
          severity: HEADER_SEVERITY[headerName] || 'medium',
          pass: !!headerValue,
          scoreModifier: headerValue ? 0 : -10,
          result: headerValue ? 'present' : 'missing',
        })
      }

      warnings.push('Mozilla Observatory API不可用，使用简化检测模式')
    }

    const result: HeadersResult = {
      url: cleanUrl,
      headers,
      score: scanResult?.score ?? 0,
      grade: scanResult?.grade ?? 'F',
      warnings,
      source: scanResult ? 'Mozilla Observatory' : '本地检测',
      testsFailed: scanResult?.tests_failed ?? 0,
      testsPassed: scanResult?.tests_passed ?? 0,
      testsQuantity: scanResult?.tests_quantity ?? 0,
    }

    try {
      await c.env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 3600 })
    } catch {}

    return c.json(result)
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500)
  }
})
