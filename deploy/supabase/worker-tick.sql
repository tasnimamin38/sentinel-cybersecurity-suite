-- Install only after sentinel-staging-api has a healthy /readyz endpoint.
-- The stored cron command reads secrets from Vault at execution time.
-- It does not embed decrypted credentials in cron.job.command.

CREATE EXTENSION IF NOT EXISTS pg_cron WITH SCHEMA pg_catalog;
CREATE EXTENSION IF NOT EXISTS pg_net;

DO $schedule$
DECLARE
    existing_job_id bigint;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM vault.decrypted_secrets
         WHERE name = 'sentinel_worker_tick_secret'
    ) THEN
        RAISE EXCEPTION 'Required SENTINEL worker secret is missing from Vault';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM vault.decrypted_secrets
         WHERE name = 'sentinel_database_url'
    ) THEN
        RAISE EXCEPTION 'Required SENTINEL database URL is missing from Vault';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM vault.decrypted_secrets
         WHERE name = 'sentinel_api_base_url'
    ) THEN
        PERFORM vault.create_secret(
            'https://sentinel-staging-api-mpir.onrender.com',
            'sentinel_api_base_url',
            'SENTINEL staging API origin used by the scheduled worker trigger'
        );
    END IF;

    SELECT jobid
      INTO existing_job_id
      FROM cron.job
     WHERE jobname = 'sentinel-worker-tick';

    IF existing_job_id IS NOT NULL THEN
        PERFORM cron.unschedule(existing_job_id);
    END IF;

    PERFORM cron.schedule(
        'sentinel-worker-tick',
        '* * * * *',
        $job$
        SELECT net.http_post(
            url := (
                SELECT decrypted_secret
                  FROM vault.decrypted_secrets
                 WHERE name = 'sentinel_api_base_url'
            ) || '/internal/worker/tick',
            headers := jsonb_build_object(
                'Content-Type',
                'application/json',
                'X-Sentinel-Worker-Secret',
                (
                    SELECT decrypted_secret
                      FROM vault.decrypted_secrets
                     WHERE name = 'sentinel_worker_tick_secret'
                )
            ),
            body := '{}'::jsonb,
            timeout_milliseconds := 10000
        );
        $job$
    );
END
$schedule$;

-- Verification (does not disclose secret values):
-- SELECT jobid, jobname, schedule, active FROM cron.job
--  WHERE jobname = 'sentinel-worker-tick';
-- SELECT start_time, end_time, status, return_message
--   FROM cron.job_run_details
--  WHERE jobid = (SELECT jobid FROM cron.job WHERE jobname = 'sentinel-worker-tick')
--  ORDER BY start_time DESC LIMIT 10;

-- Disable before changing the API URL or tick secret:
-- SELECT cron.unschedule(jobid) FROM cron.job
--  WHERE jobname = 'sentinel-worker-tick';
