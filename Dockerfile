FROM archlinux:base as builder


WORKDIR /app

COPY ./ /app

RUN pacman -Syu -q --noconfirm
RUN pacman -S llvm clang libbpf make go -q --noconfirm

RUN make

FROM archlinux:base

WORKDIR /app

COPY --from=builder /app/bin/hide-pid /app

ENTRYPOINT ["./hide-pid"]
