// Simulate someone editing a managed file outside Terraform (drift).
import { writeFileSync } from "node:fs";
import { join } from "node:path";

export default function between(workdir) {
  writeFileSync(join(workdir, "out", "drift.txt"), "edited by hand");
}
