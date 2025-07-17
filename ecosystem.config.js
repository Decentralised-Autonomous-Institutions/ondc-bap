module.exports = {
  apps: [
    {
      name: 'ondc-bap-server',
      script: './target/release/ondc-bap',
      // Set working directory to project root so config/ is found
      cwd: './',
      env: {
        ONDC_ENV: 'staging',
        RUST_LOG: 'ondc_bap=info,tower_http=debug'
      },
      env_production: {
        ONDC_ENV: 'production',
        RUST_LOG: 'ondc_bap=info'
      },
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      error_file: './logs/err.log',
      out_file: './logs/out.log',
      log_file: './logs/combined.log',
      time: true
    }
  ]
};