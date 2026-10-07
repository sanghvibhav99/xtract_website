import { NextResponse } from "next/server";
import {
  createSessionValue,
  COOKIE_NAME,
  SESSION_DURATION
} from "../../../lib/session";

export const runtime = "edge";

export async function POST(request) {
  try {
    const formData = await request.formData();

    const token = formData.get("cf-turnstile-response");

    if (!token || typeof token !== "string") {
      return NextResponse.redirect(
        new URL("/?error=verification", request.url)
      );
    }

    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          secret: process.env.TURNSTILE_SECRET_KEY,
          response: token
        })
      }
    );

    const result = await response.json();

    if (!result.success) {
      return NextResponse.redirect(
        new URL("/?error=verification", request.url)
      );
    }

    const session = await createSessionValue();

    const redirectResponse = NextResponse.redirect(
      new URL("/", request.url)
    );

    redirectResponse.cookies.set({
      name: COOKIE_NAME,
      value: session,
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
      maxAge: SESSION_DURATION
    });

    return redirectResponse;
  } catch {
    return NextResponse.redirect(
      new URL("/?error=verification", request.url)
    );
  }
}