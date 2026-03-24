import { useCallback } from 'react'

const preloadedTools = new Set<string>()

const toolLoaders: Record<string, () => Promise<unknown>> = {
  'json-formatter': () => import('@/tools/json-formatter/index'),
  'base64': () => import('@/tools/base64/index'),
  'url-encode': () => import('@/tools/url-encode/index'),
  'jwt-decoder': () => import('@/tools/jwt-decoder/index'),
  'uuid-generator': () => import('@/tools/uuid-generator/index'),
  'hash-calculator': () => import('@/tools/hash-calculator/index'),
  'password-gen': () => import('@/tools/password-gen/index'),
  'timestamp': () => import('@/tools/timestamp/index'),
  'case-converter': () => import('@/tools/case-converter/index'),
  'lorem-ipsum': () => import('@/tools/lorem-ipsum/index'),
  'color-picker': () => import('@/tools/color-picker/index'),
  'markdown-preview': () => import('@/tools/markdown-preview/index'),
  'regex-tester': () => import('@/tools/regex-tester/index'),
  'number-base': () => import('@/tools/number-base/index'),
  'text-counter': () => import('@/tools/text-counter/index'),
  'aes-encrypt': () => import('@/tools/aes-encrypt/index'),
  'ascii-table': () => import('@/tools/ascii-table/index'),
  'bcrypt': () => import('@/tools/bcrypt/index'),
  'binary-text': () => import('@/tools/binary-text/index'),
  'box-shadow-gen': () => import('@/tools/box-shadow-gen/index'),
  'calendar-gen': () => import('@/tools/calendar-gen/index'),
  'cert-decoder': () => import('@/tools/cert-decoder/index'),
  'color-blindness': () => import('@/tools/color-blindness/index'),
  'color-palette': () => import('@/tools/color-palette/index'),
  'contrast-checker': () => import('@/tools/contrast-checker/index'),
  'cron-parser': () => import('@/tools/cron-parser/index'),
  'css-formatter': () => import('@/tools/css-formatter/index'),
  'css-gradient': () => import('@/tools/css-gradient/index'),
  'csv-viewer': () => import('@/tools/csv-viewer/index'),
  'curl-converter': () => import('@/tools/curl-converter/index'),
  'date-calc': () => import('@/tools/date-calc/index'),
  'duration-format': () => import('@/tools/duration-format/index'),
  'faker-data': () => import('@/tools/faker-data/index'),
  'hex-encode': () => import('@/tools/hex-encode/index'),
  'hmac': () => import('@/tools/hmac/index'),
  'html-entities': () => import('@/tools/html-entities/index'),
  'http-headers': () => import('@/tools/http-headers/index'),
  'http-status': () => import('@/tools/http-status/index'),
  'ip-subnet': () => import('@/tools/ip-subnet/index'),
  'js-formatter': () => import('@/tools/js-formatter/index'),
  'json-to-type': () => import('@/tools/json-to-type/index'),
  'jwt-generator': () => import('@/tools/jwt-generator/index'),
  'line-sorter': () => import('@/tools/line-sorter/index'),
  'mime-types': () => import('@/tools/mime-types/index'),
  'morse-code': () => import('@/tools/morse-code/index'),
  'nanoid-gen': () => import('@/tools/nanoid-gen/index'),
  'objectid-gen': () => import('@/tools/objectid-gen/index'),
  'placeholder-img': () => import('@/tools/placeholder-img/index'),
  'punycode': () => import('@/tools/punycode/index'),
  'qrcode': () => import('@/tools/qrcode/index'),
  'rot13': () => import('@/tools/rot13/index'),
  'rsa-keygen': () => import('@/tools/rsa-keygen/index'),
  'sql-formatter': () => import('@/tools/sql-formatter/index'),
  'ssh-keygen': () => import('@/tools/ssh-keygen/index'),
  'string-escape': () => import('@/tools/string-escape/index'),
  'tailwind-colors': () => import('@/tools/tailwind-colors/index'),
  'text-diff': () => import('@/tools/text-diff/index'),
  'text-similarity': () => import('@/tools/text-similarity/index'),
  'text-transform': () => import('@/tools/text-transform/index'),
  'timezone-convert': () => import('@/tools/timezone-convert/index'),
  'toml-json': () => import('@/tools/toml-json/index'),
  'ulid-gen': () => import('@/tools/ulid-gen/index'),
  'unicode-convert': () => import('@/tools/unicode-convert/index'),
  'url-parser': () => import('@/tools/url-parser/index'),
  'user-agent': () => import('@/tools/user-agent/index'),
  'xml-formatter': () => import('@/tools/xml-formatter/index'),
  'yaml-json': () => import('@/tools/yaml-json/index'),
  'ip-lookup': () => import('@/tools/ip-lookup/index'),
  'dns-lookup': () => import('@/tools/dns-lookup/index'),
  'ai-regex': () => import('@/tools/ai-regex/index'),
  'ai-sql': () => import('@/tools/ai-sql/index'),
  'ai-code-explain': () => import('@/tools/ai-code-explain/index'),
  'ai-code-review': () => import('@/tools/ai-code-review/index'),
  'svg-optimizer': () => import('@/tools/svg-optimizer/index'),
  'svg-to-data-uri': () => import('@/tools/svg-to-data-uri/index'),
  'favicon-gen': () => import('@/tools/favicon-gen/index'),
  'exif-reader': () => import('@/tools/exif-reader/index'),
  'color-extractor': () => import('@/tools/color-extractor/index'),
  'image-compress': () => import('@/tools/image-compress/index'),
  'image-convert': () => import('@/tools/image-convert/index'),
  'image-resize': () => import('@/tools/image-resize/index'),
  'gitignore-gen': () => import('@/tools/gitignore-gen/index'),
  'license-gen': () => import('@/tools/license-gen/index'),
  'readme-gen': () => import('@/tools/readme-gen/index'),
  'conventional-commit': () => import('@/tools/conventional-commit/index'),
  'semver-calc': () => import('@/tools/semver-calc/index'),
  'openapi-viewer': () => import('@/tools/openapi-viewer/index'),
  'json-schema-gen': () => import('@/tools/json-schema-gen/index'),
  'exchange-rate': () => import('@/tools/exchange-rate/index'),
  'api-playground': () => import('@/tools/api-playground/index'),
  'qrcode-reader': () => import('@/tools/qrcode-reader/index'),
  'json-path': () => import('@/tools/json-path/index'),
  'json-to-csv': () => import('@/tools/json-to-csv/index'),
  'math-eval': () => import('@/tools/math-eval/index'),
  'html-preview': () => import('@/tools/html-preview/index'),
  'meta-tag-gen': () => import('@/tools/meta-tag-gen/index'),
  'hash-verify': () => import('@/tools/hash-verify/index'),
  'jwt-verifier': () => import('@/tools/jwt-verifier/index'),
  'password-strength': () => import('@/tools/password-strength/index'),
  'json-gen': () => import('@/tools/json-gen/index'),
  'number-unit': () => import('@/tools/number-unit/index'),
  'data-storage': () => import('@/tools/data-storage/index'),
  'sql-gen': () => import('@/tools/sql-gen/index'),
  'regex-gen': () => import('@/tools/regex-gen/index'),
  'color-space': () => import('@/tools/color-space/index'),
  'epoch-formats': () => import('@/tools/epoch-formats/index'),
  'aspect-ratio': () => import('@/tools/aspect-ratio/index'),
  'css-unit-convert': () => import('@/tools/css-unit-convert/index'),
  'roman-numeral': () => import('@/tools/roman-numeral/index'),
  'port-reference': () => import('@/tools/port-reference/index'),
  'email-validate': () => import('@/tools/email-validate/index'),
  'whois-lookup': () => import('@/tools/whois-lookup/index'),
  'ssl-checker': () => import('@/tools/ssl-checker/index'),
  'headers-check': () => import('@/tools/headers-check/index'),
  'prime-checker': () => import('@/tools/prime-checker/index'),
  'gcd-lcm': () => import('@/tools/gcd-lcm/index'),
}

export function usePreloadTool(toolId: string) {
  const preload = useCallback(() => {
    if (preloadedTools.has(toolId)) return
    const loader = toolLoaders[toolId]
    if (loader) {
      loader().then(() => {
        preloadedTools.add(toolId)
      }).catch(() => {})
    }
  }, [toolId])

  return { preload }
}

export function preloadTool(toolId: string) {
  if (preloadedTools.has(toolId)) return
  const loader = toolLoaders[toolId]
  if (loader) {
    loader().then(() => {
      preloadedTools.add(toolId)
    }).catch(() => {})
  }
}
