// Create or update a comment on the current PR.
// The marker is keyed on the comment key and image repository (no tag/digest), so new
// commits replace the previous result while each key (trivy, grype, sbom) keeps its own comment.
const maxBody = 65536;
const truncationNotice = '\n\n> ⚠️ Output truncated — see the workflow logs and artifacts for the full report.';

module.exports = async function post({ github, context, core, key, title, image, summary }) {
  const repository = image.replace(/@.*$/, '').replace(/:[^/]*$/, '');
  const marker = `<!-- ci-image-scan:${key}:${repository} -->`;
  const header = `## ${title}\n\n`;

  let body = marker + '\n' + header + summary;
  if (body.length > maxBody) {
    body = body.slice(0, maxBody - truncationNotice.length) + truncationNotice;
  }

  try {
    const comments = await github.paginate(github.rest.issues.listComments, {
      owner: context.repo.owner,
      repo: context.repo.repo,
      issue_number: context.issue.number,
      per_page: 100,
    });
    const existing = comments.find(c => c.body?.includes(marker));

    if (existing) {
      await github.rest.issues.updateComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        comment_id: existing.id,
        body,
      });
    } else {
      await github.rest.issues.createComment({
        owner: context.repo.owner,
        repo: context.repo.repo,
        issue_number: context.issue.number,
        body,
      });
    }
  } catch (err) {
    if (err.status === 403) {
      core.warning(`Skipping PR comment: ${err.message}`);
    } else {
      throw err;
    }
  }
};
