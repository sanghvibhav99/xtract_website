import "./globals.css";

export const metadata = {
  title: "Archive",
  description: "Archive"
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}