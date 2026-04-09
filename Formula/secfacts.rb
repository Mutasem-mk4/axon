class Secfacts < Formula
  desc "High-performance security evidence normalization & correlation engine"
  homepage "https://github.com/secfacts/secfacts"
  url "https://github.com/secfacts/secfacts/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "REPLACE_WITH_ACTUAL_SHA256" # Use `brew fetch --head secfacts` to get this
  license "Apache-2.0"

  depends_on "go" => :build

  def install
    ENV["CGO_ENABLED"] = "0"
    ldflags = %W[
      -s -w
      -X github.com/secfacts/secfacts/cmd/secfacts.version=#{version}
    ]
    
    # Build the binary
    system "go", "build", *std_go_args(ldflags: ldflags), "./cmd/secfacts"
    
    # Install documentation
    doc.install "README.md"
    doc.install "LICENSE"
    
    # Install examples
    (share/"secfacts/examples").install "examples/complex.sarif"
  end

  test do
    # Verify the binary runs and returns help
    assert_match "secfacts is a high-performance security evidence normalization engine",
                 shell_output("#{bin}/secfacts --help")
                 
    # Test the scan command with help output
    assert_match "Scan a security report",
                 shell_output("#{bin}/secfacts scan --help")
  end
end
