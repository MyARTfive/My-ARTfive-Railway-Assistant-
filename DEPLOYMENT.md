# My ARTfive! Cloudflare deployment

The repository contains a manually triggered GitHub Actions workflow at
`.github/workflows/manual-cloudflare-deploy.yml`.

## Required GitHub Actions secrets

Configure these in the repository's Settings → Secrets and variables → Actions:

- `CLOUDFLARE_API_TOKEN`: a Cloudflare API token with permission to deploy Workers and manage the bound D1 database.
- `CLOUDFLARE_ACCOUNT_ID`: the Cloudflare account ID.

Never put either value in source code, a browser page, or a committed configuration file.

## Preview deployment

After the workflow file is present on the repository's default branch, open
Actions → My ARTfive! Manual Cloudflare Deployment, choose the branch to deploy,
select `preview`, and run it.

Preview uses the separately named Worker `my-artfive-railway-assistant-preview`
and the configured Preview D1 database ID in `wrangler.jsonc`. It does not
publish the Production Worker.

## Production deployment

Production deployment is available only when the workflow is run from the
`main` branch and the operator types this exact confirmation:

`I APPROVE PRODUCTION DEPLOY`

The workflow is manual; it does not deploy Production on a push or pull request.
For additional human review, configure GitHub's `production` environment with
required reviewers before enabling Production use.

## Important

A code draft saved in Owner Option 11 is not a deployment. The Owner must first
review and merge approved source changes through the normal repository process.
Do not use Production deployment for unreviewed Preview changes.
