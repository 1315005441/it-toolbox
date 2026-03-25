import { Hono } from 'hono'
import type { Env } from '../[[route]]'

export const headersCheckRoute = new Hono<{ Bindings: Env }>()

interface HeaderCheck {
  name: string
  present: boolean
  value?: string
  recommendation: string
  severity: 'high' | 'medium' | 'low'
}

interface HeadersResult {
  url: string
  headers: HeaderCheck[]
  score: number
  grade: string
  warnings: string[]
}

const SECURITY_HEADERS_CONFIG = [
  {
    name: 'Strict-Transport-Security',
    recommendation: '启用HSTS强制HTTPS连接，建议设置max-age至少31536000秒',
    severity: 'high' as const,
    weight: 20,
  },
  {
    name: 'Content-Security-Policy',
    recommendation: '设置CSP限制资源加载来源，防止XSS攻击',
    severity: 'high' as const,
    weight: 20,
  },
  {
    name: 'X-Content-Type-Options',
    recommendation: '设置为nosniff防止MIME类型嗅探',
    severity: 'medium' as const,
    weight: 10,
  },
  {
    name: 'X-Frame-Options',
    recommendation: '设置为DENY或SAMEORIGIN防止点击劫持',
    severity: 'medium' as const,
    weight: 10,
  },
  {
    name: 'X-XSS-Protection',
    recommendation: '设置为1; mode=block启用XSS过滤器（现代浏览器中CSP更有效，已逐渐被淘汰）',
    severity: 'low' as const,
    weight: 5,
  },
  {
    name: 'Referrer-Policy',
    recommendation: '设置为strict-origin-when-cross-origin控制Referrer信息',
    severity: 'low' as const,
    weight: 5,
  },
  {
    name: 'Permissions-Policy',
    recommendation: '限制浏览器功能访问（摄像头、麦克风、地理位置等）',
    severity: 'medium' as const,
    weight: 10,
  },
  {
    name: 'Cross-Origin-Opener-Policy',
    recommendation: '设置为same-origin防止跨源信息泄露',
    severity: 'medium' as const,
    weight: 10,
  },
  {
    name: 'Cross-Origin-Resource-Policy',
    recommendation: '设置为same-origin防止跨源资源加载',
    severity: 'medium' as const,
    weight: 10,
  },
  {
    name: 'Cross-Origin-Embedder-Policy',
    recommendation: '设置为require-corp增强跨源隔离',
    severity: 'low' as const,
    weight: 5,
  },
]

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

  const cacheKey = `cache:headers:${cleanUrl}`
  try {
    const cached = await c.env.CACHE.get(cacheKey)
    if (cached) {
      return c.json({ ...JSON.parse(cached), cached: true })
    }
  } catch {}

  try {
    const res = await fetch(cleanUrl, {
      method: 'GET',
      redirect: 'follow',
      headers: {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      },
    })

    const warnings: string[] = []
    const allHeaders: Record<string, string> = {}
    res.headers.forEach((value, key) => {
      allHeaders[key.toLowerCase()] = value
    })

    const headers: HeaderCheck[] = SECURITY_HEADERS_CONFIG.map(config => {
      const headerKey = config.name.toLowerCase()
      const headerValue = allHeaders[headerKey] || null
      
      return {
        name: config.name,
        present: headerValue !== null,
        value: headerValue || undefined,
        recommendation: config.recommendation,
        severity: config.severity,
      }
    })

    let score = 0
    let totalWeight = 0
    
    SECURITY_HEADERS_CONFIG.forEach((config, index) => {
      totalWeight += config.weight
      if (headers[index].present) {
        score += config.weight
      }
    })

    const hstsHeader = headers.find(h => h.name === 'Strict-Transport-Security')
    if (hstsHeader?.present && hstsHeader.value) {
      const maxAgeMatch = hstsHeader.value.match(/max-age=(\d+)/i)
      if (maxAgeMatch) {
        const maxAge = parseInt(maxAgeMatch[1], 10)
        if (maxAge < 31536000) {
          warnings.push(`HSTS max-age值过小（${maxAge}秒），建议至少31536000秒（1年）`)
        }
        if (!hstsHeader.value.toLowerCase().includes('includesubdomains')) {
          warnings.push('HSTS未包含includeSubDomains指令')
        }
        if (!hstsHeader.value.toLowerCase().includes('preload')) {
          warnings.push('HSTS未包含preload指令，无法加入浏览器预加载列表')
        }
      }
    }

    const cspHeader = headers.find(h => h.name === 'Content-Security-Policy')
    if (cspHeader?.present && cspHeader.value) {
      if (cspHeader.value.includes("'unsafe-inline'")) {
        warnings.push("CSP包含'unsafe-inline'，降低了XSS防护能力")
      }
      if (cspHeader.value.includes("'unsafe-eval'")) {
        warnings.push("CSP包含'unsafe-eval'，降低了XSS防护能力")
      }
      if (cspHeader.value.includes('*')) {
        warnings.push('CSP使用通配符(*)，降低了安全性')
      }
    }

    const xFrameHeader = headers.find(h => h.name === 'X-Frame-Options')
    if (xFrameHeader?.present && xFrameHeader.value) {
      const value = xFrameHeader.value.toUpperCase()
      if (value !== 'DENY' && value !== 'SAMEORIGIN') {
        warnings.push(`X-Frame-Options值应为DENY或SAMEORIGIN，当前为${xFrameHeader.value}`)
      }
    }

    const percentageScore = Math.round((score / totalWeight) * 100)

    let grade = 'F'
    if (percentageScore >= 95) grade = 'A+'
    else if (percentageScore >= 90) grade = 'A'
    else if (percentageScore >= 80) grade = 'B'
    else if (percentageScore >= 70) grade = 'C'
    else if (percentageScore >= 60) grade = 'D'
    else if (percentageScore >= 50) grade = 'E'

    const result: HeadersResult = {
      url: cleanUrl,
      headers,
      score: percentageScore,
      grade,
      warnings,
    }

    try {
      await c.env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 3600 })
    } catch {}

    return c.json(result)
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500)
  }
})
