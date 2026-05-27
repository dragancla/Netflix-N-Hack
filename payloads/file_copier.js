// ===== Configuración =====
const FTP = {
  SERVER_IP: null,
  CTRL_PORT: 1337,      // deseado
  ROOT_PATH: "/",
  CHUNK: 2000000,
  DEBUG: true
};

// ===== Extiende SYSCALL con números del payload Lua =====
// Si ya existen en tu objeto SYSCALL, estos complementan lo faltante.
if (!globalThis.SYSCALL) globalThis.SYSCALL = {};
Object.assign(SYSCALL, {
  // ya presentes en tu exploit:
  read: SYSCALL.read ?? 0x3n,
  write: SYSCALL.write ?? 0x4n,
  open: SYSCALL.open ?? 0x5n,
  close: SYSCALL.close ?? 0x6n,
  getsockname: SYSCALL.getsockname ?? 0x20n,
  accept: SYSCALL.accept ?? 0x1en,
  socket: SYSCALL.socket ?? 0x61n,
  connect: SYSCALL.connect ?? 0x62n,
  bind: SYSCALL.bind ?? 0x68n,
  setsockopt: SYSCALL.setsockopt ?? 0x69n,
  listen: SYSCALL.listen ?? 0x6an,
  netgetiflist: SYSCALL.netgetiflist ?? 0x7dn,
  // añadidos de Lua:
  stat: SYSCALL.stat ?? 0xBCn,        // 188
  getdents: SYSCALL.getdents ?? 0x110n, // 272
  mkdir: SYSCALL.mkdir ?? 0x88n,      // 136
  rmdir: SYSCALL.rmdir ?? 0x89n,      // 137
  rename: SYSCALL.rename ?? 0x80n,    // 128
  unlink: SYSCALL.unlink ?? 0xAn,     // 10
  lseek: SYSCALL.lseek ?? 0x1DEn      // 478
});

function dbg(msg) { try { logger.log("[filecopier] " + msg); } catch (_) {} }
function notify(msg) { try { send_notification(msg); } catch (_) {} }

// ===== FS =====
function open_read(path) { const p = alloc_string(path); const fd = syscall(SYSCALL.open, p, O_RDONLY); return Number(fd); }
function open_write(path, { create, append, truncate }) {
  let flags = O_RDWR;
  if (create) flags |= O_CREAT;
  if (append) flags |= O_APPEND;
  if (truncate) flags |= O_TRUNC;
  const p = alloc_string(path);
  const fd = syscall(SYSCALL.open, p, flags);
  return Number(fd);
}
function close_fd(fd) { syscall(SYSCALL.close, BigInt(fd)); }
function read_fd(fd, bufAddr, len) { const r = syscall(SYSCALL.read, BigInt(fd), bufAddr, BigInt(len)); return Number(r); }
function write_fd(fd, bufAddr, len) { const r = syscall(SYSCALL.write, BigInt(fd), bufAddr, BigInt(len)); return Number(r); }

function sleepFor2(sleepDuration) {
    var now = new Date().getTime();
    while(new Date().getTime() < now + sleepDuration){ /* Do nothing */ }
}

// ===== Bootstrap =====
(function main_copy() {
  try {
    logger.init();
    logger.log("init");

    logger.log("scanning /mnt/usb0..7 for download0...");
    const usb_names = ["download0.dat"];
    let fromPath = null;
    for (let u = 0; u < 8 && !fromPath; u++) {
        for (const name of usb_names) {
            const p = "/mnt/usb" + u + "/" + name;
            if (file_exists(p)) { fromPath = p; break; }
        }
    }

    if (!fromPath) {
      logger.log("Can't find download0.dat on usb storage");
      return;
    } else {
      logger.log("found " + fromPath);
    }
    
    //const fromPath = "/app0/eboot.bin";
    //const toPath = "/download0/GAMEDATA/tmp/test.bin";
    const toPath = "/user/download/PPSA01650/download0.dat";

    const fromFd = open_read(fromPath);
    logger.log("open read");
    const toFd = open_write(toPath, { create: true, append: false, truncate: true });
    logger.log("open write");

    const buf = malloc(FTP.CHUNK);
    logger.log("malloc");

    let writeChunks = 0;

    while (true) {
      const n = read_fd(fromFd, buf, FTP.CHUNK);
      if (n <= 0) break;
      const w = write_fd(toFd, buf, n);
      //if (w < n) { logger.log("550 File write error\r\n"); break; }

      writeChunks++;
      if ((writeChunks - 1) % 10 === 0) {
        logger.log((writeChunks * FTP.CHUNK) + " bytes written");
        logger.log("n=" + n + ", w = " + w);
      }
      // if (writeChunks % 100 === 0) {
      //   logger.log("10s sleep to be safe");
      //   sleepFor2(10000);
      // }
      if (n > FTP.CHUNK || w > FTP.CHUNK) {
        logger.log("wrong values");
        logger.log("n=" + n + ", w = " + w);
      }
    }
    logger.log("now closing the fds");
    close_fd(fromFd);
    close_fd(toFd);
    logger.log("File copied");
    logger.flush();

    logger.log("Starting infinite loop");

    while(true) {}
  } catch (e) {
    dbg("ERROR filecopy: " + e.message);
    logger.flush();
  }
})();
