import { Form, Link, useSearchParams } from "react-router";
import { adminUrl, useAdminPath } from "./admin-path";
import type { Route } from "./+types/users";
import { call, type Paged } from "../../lib/api";
import { buildMeta } from "../../lib/seo";
import { Empty, PageHeader, Pill, formatDate, formatRelative } from "../../components/ui";

export function meta({ location }: Route.MetaArgs) {
  return buildMeta({
    title: "Users",
    description: "Manage accounts.",
    path: location.pathname,
    noindex: true,
  });
}

interface AdminUser {
  id: string;
  email: string;
  name: string;
  emailVerified: boolean;
  role: string;
  status: string;
  twoFactorEnabled: boolean;
  createdAt: string;
  lastLoginAt: string | null;
}

export async function loader({ request }: Route.LoaderArgs) {
  const incoming = new URL(request.url).searchParams;
  // Only allowlisted filters are forwarded; anything else a caller appends is
  // dropped rather than passed to the API.
  const query = new URLSearchParams();
  for (const key of ["q", "status", "verified", "role", "cursor"]) {
    const value = incoming.get(key);
    if (value) query.set(key, value);
  }
  query.set("limit", "50");

  const result = await call<Paged<AdminUser>>(`/admin/users?${query}`, { request });
  return {
    users: result.data?.items ?? [],
    nextCursor: result.data?.page.nextCursor ?? null,
    error: result.error,
  };
}

export default function AdminUsers({ loaderData }: Route.ComponentProps) {
  const adminPath = useAdminPath();
  const [params] = useSearchParams();

  /*
   * The filters on screen, minus the cursor.
   *
   * `cursor` is where THIS page of the table starts, and carrying it into an
   * export would silently drop everyone before it — a file that looks complete
   * and is missing the first few hundred people.
   */
  const exportQuery = new URLSearchParams();
  for (const key of ["q", "status", "verified", "role"]) {
    const value = params.get(key);
    if (value) exportQuery.set(key, value);
  }

  return (
    <>
      <PageHeader
        title="Users"
        description="Search by email, name or user id."
        actions={
          /*
           * A plain link, not a fetch.
           *
           * The browser has to do this navigation itself for the download to
           * reach the disk: `content-disposition: attachment` is an instruction
           * to the BROWSER, and a fetch would hand the file to JavaScript
           * instead, which would then have to rebuild it as a blob to save it.
           * A GET carries the session cookie same-origin, and the API exempts
           * safe methods from the origin guard, so this works as written.
           *
           * It carries whatever filters are on screen, so what downloads is
           * what the operator is looking at rather than a different population
           * with the same name.
           */
          <a className="btn btn-outline" href={`/api/v1/admin/users/export?${exportQuery}`}>
            Download CSV
          </a>
        }
      />

      <Form
        method="get"
        style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginBottom: "1.5rem" }}
      >
        <input
          className="input"
          name="q"
          type="search"
          placeholder="Email, name or usr_…"
          defaultValue={params.get("q") ?? ""}
          aria-label="Search users"
          style={{ maxWidth: "22rem" }}
        />
        <select
          className="input"
          name="status"
          defaultValue={params.get("status") ?? ""}
          aria-label="Filter by status"
          style={{ maxWidth: "11rem" }}
        >
          <option value="">Any status</option>
          <option value="active">Active</option>
          <option value="suspended">Suspended</option>
          <option value="deleted">Deleted</option>
        </select>
        <select
          className="input"
          name="verified"
          defaultValue={params.get("verified") ?? ""}
          aria-label="Filter by verification"
          style={{ maxWidth: "11rem" }}
        >
          <option value="">Any verification</option>
          <option value="true">Verified</option>
          <option value="false">Unverified</option>
        </select>
        <button type="submit" className="btn btn-ink">
          Search
        </button>
      </Form>

      {loaderData.users.length === 0 ? (
        <Empty title="No users match">Try a different search or clear the filters.</Empty>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <caption className="sr-only">Accounts matching the current filters</caption>
            <thead>
              <tr>
                <th scope="col">User</th>
                <th scope="col">Status</th>
                <th scope="col">Role</th>
                <th scope="col">Joined</th>
                <th scope="col">Last seen</th>
              </tr>
            </thead>
            <tbody>
              {loaderData.users.map((user) => (
                <tr key={user.id}>
                  <td>
                    <Link to={adminUrl(adminPath, `users/${user.id}`)} style={{ fontWeight: 500 }}>
                      {user.email}
                    </Link>
                    <br />
                    <span style={{ fontSize: "var(--text-micro)", color: "var(--color-muted)" }}>
                      {user.name}
                    </span>
                  </td>
                  <td style={{ display: "flex", gap: "0.375rem", flexWrap: "wrap" }}>
                    <Pill
                      tone={
                        user.status === "active"
                          ? "positive"
                          : user.status === "suspended"
                            ? "critical"
                            : "neutral"
                      }
                    >
                      {user.status}
                    </Pill>
                    {!user.emailVerified && <Pill tone="caution">unverified</Pill>}
                    {user.twoFactorEnabled && <Pill tone="positive">2FA</Pill>}
                  </td>
                  <td style={{ textTransform: "capitalize", color: "var(--color-muted)" }}>
                    {user.role.replace("_", " ")}
                  </td>
                  <td style={{ whiteSpace: "nowrap", color: "var(--color-muted)" }}>
                    {formatDate(user.createdAt)}
                  </td>
                  <td style={{ whiteSpace: "nowrap", color: "var(--color-muted)" }}>
                    {user.lastLoginAt ? formatRelative(user.lastLoginAt) : "never"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {loaderData.nextCursor && (
        <p style={{ marginTop: "1.5rem" }}>
          <Link
            to={adminUrl(adminPath, `users?cursor=${encodeURIComponent(loaderData.nextCursor)}`)}
            className="btn btn-quiet"
          >
            Next page
          </Link>
        </p>
      )}
    </>
  );
}
