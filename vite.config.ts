import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { VitePWA } from 'vite-plugin-pwa'
import path from 'path'

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['favicon.svg', 'favicon-32x32.png', 'apple-touch-icon.png'],
      manifest: {
        name: 'IT Toolbox',
        short_name: 'IT Toolbox',
        description: '开发者工具箱，150+ 实用工具',
        theme_color: '#10b981',
        background_color: '#0f172a',
        display: 'standalone',
        orientation: 'portrait-primary',
        scope: '/',
        start_url: '/',
        icons: [
          {
            src: 'pwa-192x192.png',
            sizes: '192x192',
            type: 'image/png',
          },
          {
            src: 'pwa-512x512.png',
            sizes: '512x512',
            type: 'image/png',
          },
          {
            src: 'favicon.svg',
            sizes: 'any',
            type: 'image/svg+xml',
            purpose: 'any',
          },
        ],
        categories: ['developer', 'utilities', 'productivity'],
        shortcuts: [
          {
            name: 'JSON 格式化',
            short_name: 'JSON',
            url: '/tool/json-formatter',
          },
          {
            name: 'Base64 编解码',
            short_name: 'Base64',
            url: '/tool/base64',
          },
        ],
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,ico,png,svg,woff2}'],
        navigateFallback: '/index.html',
        navigateFallbackDenylist: [/^\/api/],
        maximumFileSizeToCacheInBytes: 5 * 1024 * 1024,
        runtimeCaching: [
          {
            urlPattern: /^https:\/\/fonts\.googleapis\.com\/.*/i,
            handler: 'CacheFirst',
            options: {
              cacheName: 'google-fonts-cache',
              expiration: {
                maxEntries: 10,
                maxAgeSeconds: 60 * 60 * 24 * 365,
              },
              cacheableResponse: {
                statuses: [0, 200],
              },
            },
          },
          {
            urlPattern: /^https:\/\/fonts\.gstatic\.com\/.*/i,
            handler: 'CacheFirst',
            options: {
              cacheName: 'gstatic-fonts-cache',
              expiration: {
                maxEntries: 10,
                maxAgeSeconds: 60 * 60 * 24 * 365,
              },
              cacheableResponse: {
                statuses: [0, 200],
              },
            },
          },
          {
            urlPattern: /\.(?:js|css|woff2)$/i,
            handler: 'StaleWhileRevalidate',
            options: {
              cacheName: 'static-resources',
              expiration: {
                maxEntries: 100,
                maxAgeSeconds: 60 * 60 * 24 * 30,
              },
              cacheableResponse: {
                statuses: [0, 200],
              },
            },
          },
          {
            urlPattern: /\.(?:png|jpg|jpeg|svg|gif|webp|ico)$/i,
            handler: 'CacheFirst',
            options: {
              cacheName: 'image-resources',
              expiration: {
                maxEntries: 60,
                maxAgeSeconds: 60 * 60 * 24 * 30,
              },
              cacheableResponse: {
                statuses: [0, 200],
              },
            },
          },
        ],
      },
      devOptions: {
        enabled: false,
      },
    }),
  ],
  server: {
    host: '127.0.0.1',
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8788',
        changeOrigin: true,
        rewrite: (p) => p,
      },
    },
  },
  assetsInclude: ['**/*.wasm'],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@core': path.resolve(__dirname, './packages/core'),
      '@toolbox/types': path.resolve(__dirname, './packages/types'),
      '@it-toolbox/core': path.resolve(__dirname, './packages/core'),
      '@it-toolbox/types': path.resolve(__dirname, './packages/types'),
    },
  },
  optimizeDeps: {
    esbuildOptions: {
      target: 'esnext',
    },
  },
  esbuild: {
    target: 'esnext',
  },
  build: {
    target: 'esnext',
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          if (id.includes('node_modules')) {
            if (id.includes('/react/') || id.includes('/react-dom/')) return 'react-vendor'
            if (id.includes('@tanstack/react-router')) return 'router'
            if (id.includes('bcryptjs') || id.includes('jose')) return 'crypto-vendor'
            if (id.includes('highlight.js') || id.includes('marked')) return 'markdown-vendor'
            if (id.includes('@faker-js/faker')) return 'faker-vendor'
            if (id.includes('mathjs')) return 'math-vendor'
            if (id.includes('qrcode') || id.includes('jsqr')) return 'qrcode-vendor'
            if (id.includes('exifr') || id.includes('browser-image-compression')) return 'image-vendor'
            if (id.includes('svgo')) return 'svg-vendor'
            if (id.includes('papaparse') || id.includes('js-yaml') || id.includes('sql-formatter')) return 'data-vendor'
            if (id.includes('lucide-react')) return 'icons-vendor'
            if (id.includes('chroma-js')) return 'color-vendor'
            if (id.includes('dayjs')) return 'datetime-vendor'
            if (id.includes('diff') || id.includes('fuse.js')) return 'text-vendor'
            return 'vendor'
          }
          if (id.includes('/src/tools/')) {
            const match = id.match(/\/src\/tools\/([^/]+)\//)
            if (match) {
              const toolId = match[1]
              if (toolId.startsWith('ai-')) return 'tools-ai'
              if (toolId.includes('json') || toolId.includes('yaml') || toolId.includes('csv')) return 'tools-data'
              if (toolId.includes('encrypt') || toolId.includes('hash') || toolId.includes('jwt') || toolId.includes('key')) return 'tools-crypto'
              if (toolId.includes('color') || toolId.includes('css') || toolId.includes('gradient')) return 'tools-design'
              if (toolId.includes('image') || toolId.includes('svg') || toolId.includes('qrcode')) return 'tools-media'
              if (toolId.includes('date') || toolId.includes('time') || toolId.includes('cron')) return 'tools-datetime'
              if (toolId.includes('text') || toolId.includes('regex') || toolId.includes('case')) return 'tools-text'
              if (toolId.includes('ip') || toolId.includes('dns') || toolId.includes('http') || toolId.includes('url')) return 'tools-network'
              return 'tools-other'
            }
          }
        },
      },
    },
  },
})
