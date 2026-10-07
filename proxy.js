import { NextResponse } from "next/server";
import { COOKIE_NAME, verifySessionValue } from "./lib/session";

export async function proxy(request) {
  const session = request.cookies.get(COOKIE_NAME)?.value;

  const valid = await verifySessionValue(session);

  if (!valid) {
    return new NextResponse("Forbidden", {
      status: 403,
      headers: {
        "Content-Type": "text/plain"
      }
    });
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/data/:path*"
  ]
};