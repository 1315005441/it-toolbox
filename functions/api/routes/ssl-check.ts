import { Hono } from 'hono'
import type { Env } from '../[[route]]'

export const sslCheckRoute = new Hono<{ Bindings: Env }>()

interface SslResult {
  domain: string
  valid: boolean
  issuer: string
  subject: string
  validFrom: string
  validTo: string
  daysRemaining: number
  serialNumber: string
  signatureAlgorithm: string
  sans: string[]
  error?: string
}

interface SslLabsCert {
  id: string
  subject: string
  serialNumber: string
  commonNames: string[]
  altNames: string[]
  notBefore: number
  notAfter: number
  issuerSubject: string
  sigAlg: string
  issues: number
  sct: boolean
  sha1Hash: string
  sha256Hash: string
  keyAlg: string
  keySize: number
}

interface SslLabsEndpoint {
  ipAddress: string
  serverName: string
  statusMessage: string
  grade: string
  gradeTrustIgnored: string
  hasWarnings: boolean
  isExceptional: boolean
  progress: number
  duration: number
  eta: number
  delegation: number
  details?: {
    certChains: Array<{
      certIds: string[]
    }>
  }
}

interface SslLabsHost {
  host: string
  port: number
  protocol: string
  isPublic: boolean
  status: string
  statusMessage: string
  startTime: number
  testTime: number
  engineVersion: string
  criteriaVersion: string
  cacheExpiryTime: number
  endpoints: SslLabsEndpoint[]
  certs: SslLabsCert[]
}

sslCheckRoute.get('/', async (c) => {
  const domain = c.req.query('domain')

  if (!domain) {
    return c.json({ error: 'domain is required' }, 400)
  }

  const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0]

  const cacheKey = `cache:ssl:${cleanDomain}`
  try {
    const cached = await c.env.CACHE.get(cacheKey)
    if (cached) {
      return c.json({ ...JSON.parse(cached), cached: true })
    }
  } catch {}

  try {
    const result: SslResult = {
      domain: cleanDomain,
      valid: false,
      issuer: 'Unknown',
      subject: cleanDomain,
      validFrom: '',
      validTo: '',
      daysRemaining: 0,
      serialNumber: '',
      signatureAlgorithm: '',
      sans: [cleanDomain],
    }

    let sslLabsSuccess = false
    let sslLabsStatus = ''

    try {
      const sslApiRes = await fetch(
        `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(cleanDomain)}&fromCache=on&maxAge=24&all=done`,
        {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
          },
        }
      )

      if (sslApiRes.ok) {
        const sslData = (await sslApiRes.json()) as SslLabsHost
        sslLabsStatus = sslData.status || ''

        if (sslData.status === 'READY' && sslData.certs && sslData.certs.length > 0) {
          const leafCert = sslData.certs[0]

          if (leafCert.issuerSubject) {
            const issuerMatch = leafCert.issuerSubject.match(/CN=([^,]+)/)
            result.issuer = issuerMatch ? issuerMatch[1] : leafCert.issuerSubject
          }

          if (leafCert.subject) {
            const subjectMatch = leafCert.subject.match(/CN=([^,]+)/)
            result.subject = subjectMatch ? subjectMatch[1] : leafCert.subject
          }

          if (leafCert.notBefore) {
            result.validFrom = new Date(leafCert.notBefore).toISOString()
          }

          if (leafCert.notAfter) {
            result.validTo = new Date(leafCert.notAfter).toISOString()
            const expiryDate = new Date(leafCert.notAfter)
            const now = new Date()
            result.daysRemaining = Math.ceil(
              (expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
            )
            result.valid = result.daysRemaining > 0
          }

          if (leafCert.serialNumber) {
            result.serialNumber = leafCert.serialNumber
          }

          if (leafCert.sigAlg) {
            result.signatureAlgorithm = leafCert.sigAlg
          }

          if (leafCert.altNames && leafCert.altNames.length > 0) {
            result.sans = leafCert.altNames
          } else if (leafCert.commonNames && leafCert.commonNames.length > 0) {
            result.sans = leafCert.commonNames
          }

          sslLabsSuccess = true
        } else if (sslData.status === 'IN_PROGRESS') {
          result.error = `SSL Labs正在评估中，请稍后重试（进度: ${sslData.endpoints?.[0]?.progress || 0}%）`
        } else if (sslData.status === 'DNS') {
          result.error = 'DNS解析中，请稍后重试'
        } else if (sslData.status === 'ERROR') {
          result.error = sslData.statusMessage || 'SSL Labs评估失败'
        }
      }
    } catch (sslLabsError) {
      console.log('SSL Labs API failed:', sslLabsError)
    }

    if (!sslLabsSuccess && !result.error) {
      try {
        const res = await fetch(`https://${cleanDomain}`, {
          method: 'HEAD',
          redirect: 'follow',
        })

        result.valid = true
        result.error = `SSL Labs API不可用（状态: ${sslLabsStatus || '未知'}），仅确认证书有效，无法获取详细信息`

        const cfTlsCipher = c.req.raw.cf?.tlsCipher as string | undefined
        if (cfTlsCipher) {
          result.signatureAlgorithm = cfTlsCipher
        }
      } catch (directError) {
        const errorMessage = (directError as Error).message
        if (
          errorMessage.includes('certificate') ||
          errorMessage.includes('SSL') ||
          errorMessage.includes('TLS')
        ) {
          return c.json({
            domain: cleanDomain,
            valid: false,
            issuer: '',
            subject: '',
            validFrom: '',
            validTo: '',
            daysRemaining: 0,
            serialNumber: '',
            signatureAlgorithm: '',
            sans: [],
            error: 'SSL证书无效或域名无法访问',
          })
        }
        result.error = `无法连接到服务器: ${errorMessage}`
      }
    }

    if (!result.validFrom && !result.validTo && !result.error) {
      result.error = '无法获取SSL证书信息，请检查域名是否正确或稍后重试'
    }

    try {
      await c.env.CACHE.put(cacheKey, JSON.stringify(result), { expirationTtl: 3600 })
    } catch {}

    return c.json(result)
  } catch (e) {
    return c.json({ error: (e as Error).message }, 500)
  }
})
