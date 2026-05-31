export default function Badge({ severity }) {
  return <span className={`badge badge-${severity}`}>{severity}</span>
}
