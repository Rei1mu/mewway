//! 程序图标：直接读仓库根目录的 `logo.ico`
//!
//! 两种存储方式都要认：
//! - **PNG 压缩**（Windows Vista 之后的图标基本都是这种，本项目 7 张全是 PNG）
//! - **未压缩 DIB**（老式图标，32bpp 的裸 BGRA）
//!
//! PNG 那部分用 `png` crate 解 —— 它本来就在依赖树里（tray-icon 带进来的），
//! 加一行直接依赖不增加任何下载或编译成本。手写 PNG 解码（zlib + 滤波器）
//! 纯属自找麻烦。

use eframe::egui;

/// 图标文件本身。编译期就嵌进可执行文件，运行时不需要旁边的 ico 还能跑。
const ICO: &[u8] = include_bytes!("../logo.ico");
const PNG_SIG: &[u8] = &[0x89, b'P', b'N', b'G'];

#[derive(Clone, Copy)]
struct Entry {
    width: u32,
    bpp: u16,
    offset: usize,
    size: usize,
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn entries() -> Vec<Entry> {
    if ICO.len() < 6 || u16_at(ICO, 2) != 1 {
        return Vec::new();
    }
    let count = u16_at(ICO, 4) as usize;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let o = 6 + i * 16;
        if o + 16 > ICO.len() {
            break;
        }
        out.push(Entry {
            // 目录里 0 表示 256
            width: match ICO[o] {
                0 => 256,
                v => v as u32,
            },
            bpp: u16_at(ICO, o + 6),
            size: u32_at(ICO, o + 8) as usize,
            offset: u32_at(ICO, o + 12) as usize,
        });
    }
    out
}

/// 挑一张最接近 `want` 的
fn pick(want: u32) -> Option<Entry> {
    let mut best: Option<Entry> = None;
    for e in entries() {
        if e.offset + e.size > ICO.len() || e.bpp != 32 {
            continue;
        }
        let better = match best {
            None => true,
            Some(b) => {
                let d = |x: &Entry| (x.width as i64 - want as i64).abs();
                d(&e) < d(&b) || (d(&e) == d(&b) && e.width > b.width)
            }
        };
        if better {
            best = Some(e);
        }
    }
    best
}

/// 解出一张图标，返回 (RGBA, 宽, 高)
pub fn rgba(want: u32) -> Option<(Vec<u8>, u32, u32)> {
    let e = pick(want)?;
    let d = &ICO[e.offset..e.offset + e.size];
    if d.starts_with(PNG_SIG) {
        decode_png(d)
    } else {
        decode_dib(d)
    }
}

fn decode_png(d: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    let mut decoder = png::Decoder::new(std::io::Cursor::new(d));
    // 调色板 / 低位深 / 灰度统统展开成 8 位 RGB(A)，省得自己分支
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().ok()?;
    let mut buf = vec![0u8; reader.output_buffer_size()?];
    let info = reader.next_frame(&mut buf).ok()?;
    let (w, h) = (info.width, info.height);
    let data = &buf[..info.buffer_size()];
    let rgba = match info.color_type {
        png::ColorType::Rgba => data.to_vec(),
        png::ColorType::Rgb => data.chunks_exact(3).flat_map(|p| [p[0], p[1], p[2], 255]).collect(),
        png::ColorType::GrayscaleAlpha => {
            data.chunks_exact(2).flat_map(|p| [p[0], p[0], p[0], p[1]]).collect()
        }
        png::ColorType::Grayscale => data.iter().flat_map(|&g| [g, g, g, 255]).collect(),
        png::ColorType::Indexed => return None,
    };
    Some((rgba, w, h))
}

/// 老式 32bpp DIB：BGRA、自下而上，头部是 BITMAPINFOHEADER
fn decode_dib(d: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    if d.len() < 40 {
        return None;
    }
    let hdr = u32_at(d, 0) as usize; // 头长度，通常 40
    let w = u32_at(d, 4) as i32;
    let h = u32_at(d, 8) as i32; // DIB 里高度是两倍（下面还跟着 AND 掩码）
    if w <= 0 || h == 0 || hdr < 40 || hdr > d.len() {
        return None;
    }
    let (w, h) = (w as u32, (h / 2).unsigned_abs());
    let stride = (w * 4) as usize;
    if hdr + stride * h as usize > d.len() {
        return None;
    }

    let mut out = vec![0u8; stride * h as usize];
    let mut any_alpha = false;
    for y in 0..h as usize {
        let src = hdr + (h as usize - 1 - y) * stride;
        out[y * stride..(y + 1) * stride].copy_from_slice(&d[src..src + stride]);
        if !any_alpha {
            any_alpha = (0..w as usize).any(|x| d[src + x * 4 + 3] != 0);
        }
    }
    if !any_alpha {
        // 不带 alpha 通道的老图标，只有 AND 掩码；当全不透明处理
        for px in out.chunks_exact_mut(4) {
            px[3] = 255;
        }
    }
    Some((out, w, h))
}

/// 给窗口用的 `egui::IconData`
pub fn icon_data(want: u32) -> egui::IconData {
    match rgba(want) {
        Some((rgba, width, height)) => egui::IconData { rgba, width, height },
        // 兜底：纯色方块也比没有图标强，而且绝不能让程序因此起不来
        None => egui::IconData {
            rgba: [0x4d, 0x9d, 0xff, 0xff].repeat((want * want) as usize),
            width: want,
            height: want,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 换 logo.ico 之后跑一下这个测试。
    /// `icon_data` 解不出来时会静默退化成一块蓝色方块，
    /// 光看界面很难发现是「图标坏了」还是「图标换了」。
    #[test]
    fn logo_ico_decodes_at_common_sizes() {
        let es = entries();
        assert!(!es.is_empty(), "logo.ico 里一个帧都读不出来");
        for want in [16u32, 32, 64, 128, 256] {
            let (rgba, w, h) = rgba(want).unwrap_or_else(|| panic!("解不出 {want}px 的图标"));
            assert!(w > 0 && h > 0, "{want}px 的图标尺寸非法");
            assert_eq!(
                rgba.len(),
                (w as usize) * (h as usize) * 4,
                "{want}px 的图标像素长度对不上"
            );
            // 至少得有点内容，全 0 也算坏
            assert!(rgba.chunks_exact(4).any(|p| p[3] > 0), "{want}px 的图标全透明");
        }
    }
}
