import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { routerBasename } from '../src/lib/basePath.js';

// BrowserRouter's `basename` prop is what makes react-router's own navigation (<Navigate>,
// <Link>, useNavigate()) honor the reverse-proxy prefix — e.g. the unauthenticated redirect to
// "/login" in App.tsx resolves to "${BASE_PATH}/login" once wired through basename, instead of
// the site root. See main.tsx for the wiring and App.tsx for the redirect itself.
describe('routerBasename', () => {
  it('passes through a non-empty reverse-proxy prefix unchanged', () => {
    assert.equal(routerBasename('/sys/ftp'), '/sys/ftp');
  });

  it("falls back to '/' when there is no prefix (root deployment)", () => {
    assert.equal(routerBasename(''), '/');
  });
});
