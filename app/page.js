import { cookies } from "next/headers";

export const dynamic = "force-dynamic";

export default async function Home() {
  const cookieStore = await cookies();
  const verified = cookieStore.get("xtract_verified")?.value;

  return (
    <>
      {!verified ? (
        <main className="gate">
          <div className="gate-box">
            <h1>Archive</h1>
            <p>Verification required.</p>

            <form action="/api/verify_turnstile" method="POST">
              <div
                className="cf-turnstile"
                data-sitekey={process.env.TURNSTILE_SITE_KEY}
                data-theme="dark"
              />

              <button type="submit">
                Enter Archive
              </button>
            </form>
          </div>
        </main>
      ) : (
        <>
          <header>
            <h1>Archive</h1>
            <p>780 images</p>
          </header>

          <div className="grid">
            {Array.from({ length: 779 }, (_, index) => {
  const groupNumber = String(index + 1).padStart(4, "0");
  const groupPath = `/data/group_${groupNumber}`;

  return (
    <div className="item" key={groupNumber}>
      <a href={groupPath}>
        <div className="number">
          Group {index + 1}
        </div>
      </a>
    </div>
  );
})}
          </div>
        </>
      )}

      <script
        src="https://challenges.cloudflare.com/turnstile/v0/api.js"
        async
        defer
      />
    </>
  );
}