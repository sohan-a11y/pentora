# Pentora — multi-stage Dockerfile
# Stage 1: Build Go tools
FROM golang:1.22-alpine AS gobuilder
WORKDIR /build
RUN apk add --no-cache git build-base
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/ffuf/ffuf/v2@latest \
 && go install github.com/hahwul/dalfox/v2@latest \
 && go install github.com/tomnomnom/waybackurls@latest \
 && go install github.com/hakluke/hakrawler@latest \
 && go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/PentestPad/subzy@latest

# Stage 2: Runtime on Kali
FROM kalilinux/kali-rolling:latest
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip git curl wget sqlmap testssl.sh \
    libimage-exiftool-perl && rm -rf /var/lib/apt/lists/*
COPY --from=gobuilder /root/go/bin/ /usr/local/bin/
RUN pip3 install --no-cache-dir --break-system-packages \
    arjun paramspider xsstrike commix wafw00f theHarvester
WORKDIR /app
COPY . /app
RUN pip3 install --no-cache-dir --break-system-packages .
RUN nuclei -update-templates -ud /opt/nuclei-templates || true
ENV NUCLEI_TEMPLATES=/opt/nuclei-templates
ENTRYPOINT ["pentora"]
CMD ["--help"]
