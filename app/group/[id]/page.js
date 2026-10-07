import Link from "next/link";
import groups from "../../../public/groups.json";

export default async function GroupPage({ params }) {
  const { id } = await params;

  const groupNumber = Number(id);

  if (
    !Number.isInteger(groupNumber) ||
    groupNumber < 1 ||
    groupNumber > 779
  ) {
    return <h1>404 - Group not found</h1>;
  }

  const group = `group_${String(groupNumber).padStart(4, "0")}`;
  const images = groups[group];

  if (!images) {
    return <h1>404 - Group not found</h1>;
  }

  return (
    <main>
      <header>
        <Link href="/">← Back to Archive</Link>
        <h1>Group {groupNumber}</h1>
        <p>{images.length} images</p>
      </header>

      <div className="grid">
        {images.map((filename) => (
          <div className="item" key={filename}>
            <a
              href={`/data/${group}/${filename}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              <img
                src={`/data/${group}/${filename}`}
                alt={filename}
                loading="lazy"
              />
              <div className="number">{filename}</div>
            </a>
          </div>
        ))}
      </div>
    </main>
  );
}