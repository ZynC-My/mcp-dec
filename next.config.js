/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: { serverComponentsExternalPackages: [] },
  // Increase body limit for binary uploads (default is 1mb)
  api: { bodyParser: { sizeLimit: '25mb' } }
};
module.exports = nextConfig;
