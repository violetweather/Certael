import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '')
  return {
    plugins: [react()],
    server: {
      host: '127.0.0.1',
      port: 4173,
      proxy: {
        '/bff': {
          target: env.CERTAEL_BFF_TARGET ?? 'https://localhost:7184',
          changeOrigin: true,
          secure: false,
        },
      },
    },
    build: {
      sourcemap: mode !== 'production',
      target: 'es2022',
    },
  }
})
