/**
 * PM2 Ecosystem Config — Paramount E-mart
 * ==========================================
 * Start with:   pm2 start ecosystem.config.js
 * Reload with:  pm2 reload paramount-store
 * Stop with:    pm2 stop paramount-store
 * Monitor with: pm2 monit
 *
 * Install PM2 once: npm install -g pm2
 * Auto-start on reboot: pm2 startup && pm2 save
 */

module.exports = {
  apps: [
    {
      // ── App identity ──────────────────────────────────
      name:        'paramount-store',
      script:      './server.js',
      cwd:         __dirname,

      // ── Instances ─────────────────────────────────────
      // Use 1 instance for simplicity and file-write safety.
      // (Multiple instances would need a shared DB for data files)
      instances:   1,
      exec_mode:   'fork',

      // ── Environment ───────────────────────────────────
      env: {
        NODE_ENV: 'development',
        PORT:     3000,
      },
      env_production: {
        NODE_ENV: 'production',
        PORT:     3000,
      },

      // ── Restart behaviour ─────────────────────────────
      autorestart:        true,
      watch:              false,       // don't restart on file change in production
      max_memory_restart: '512M',      // restart if memory exceeds 512MB
      restart_delay:      3000,        // wait 3s before restarting after crash
      max_restarts:       20,          // stop trying after 20 crashes in a row
      min_uptime:         '10s',       // consider started if alive > 10s

      // ── Logging ───────────────────────────────────────
      // PM2 log files — separate from the server's own ./logs/ folder
      out_file:     './logs/pm2-out.log',
      error_file:   './logs/pm2-error.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss',
      merge_logs:   true,

      // ── Graceful shutdown ─────────────────────────────
      // Gives the server time to finish the final backup before killing
      kill_timeout: 15000,            // 15 seconds
      listen_timeout: 8000,

      // ── Node.js args ──────────────────────────────────
      node_args: '--max-old-space-size=256',

      // ── Source maps ───────────────────────────────────
      source_map_support: false,
    }
  ]
};
