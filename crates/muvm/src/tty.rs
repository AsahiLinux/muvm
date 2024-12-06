use std::fs::File;
use std::io::{stdout, Read, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, FromRawFd};
use std::os::unix::net::{UnixListener, UnixStream};

use crate::utils::tty::*;
use anyhow::Result;
use nix::errno::Errno;
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
use nix::sys::signal::{sigprocmask, SigSet, SigmaskHow, Signal};
use nix::sys::signalfd::SignalFd;
use rustix::termios::{
    tcgetattr, tcgetwinsize, tcsetattr, ControlModes, InputModes, LocalModes, OptionalActions,
    OutputModes, SpecialCodeIndex, Termios,
};

fn process_remote_msg(
    remote: &mut UnixStream,
    is_tty: bool,
    stdout: &mut File,
    stderr: &mut File,
) -> Result<Option<u8>> {
    let mut cmd_buf = [0u8; 2];
    remote.read_exact(&mut cmd_buf)?;
    let cmd = u16::from_le_bytes(cmd_buf);
    let opc = cmd & CMD_MASK;
    if opc == CMD_WRITE_STDOUT || opc == CMD_WRITE_STDERR {
        let len = cmd as usize >> CMD_SHIFT;
        let mut data_buf = vec![0; len];
        remote.read_exact(&mut data_buf)?;
        if opc == CMD_WRITE_STDOUT || is_tty {
            stdout.write_all(&data_buf)?;
        } else {
            stderr.write_all(&data_buf)?;
        }
    } else if opc == CMD_EXIT {
        return Ok(Some((cmd >> CMD_SHIFT) as u8));
    }
    Ok(None)
}

fn process_stdin(remote: &mut UnixStream, epoll: &Epoll, stdin: &mut File) -> Result<()> {
    let mut data = [0; 4096];
    let len = stdin.read(&mut data)?;
    let data = &data[..len];
    let cmd = CMD_WRITE_STDIN | (len << CMD_SHIFT) as u16;
    remote.write_all(&cmd.to_le_bytes())?;
    if len == 0 {
        epoll.delete(stdin)?;
    } else {
        remote.write_all(data)?;
    }
    Ok(())
}

fn update_size(remote: &mut UnixStream) -> Result<()> {
    let win_sz = tcgetwinsize(stdout())?;
    let mut buf = [0; 6];
    buf[0..2].copy_from_slice(&CMD_UPDATE_SIZE.to_le_bytes());
    buf[2..4].copy_from_slice(&win_sz.ws_col.to_le_bytes());
    buf[4..6].copy_from_slice(&win_sz.ws_row.to_le_bytes());
    remote.write_all(&buf)?;
    Ok(())
}

pub struct RawTerminal(Termios);

impl RawTerminal {
    pub fn set() -> Result<RawTerminal> {
        let old_attr = tcgetattr(stdout())?;
        let mut new_attr = old_attr.clone();
        new_attr.special_codes[SpecialCodeIndex::VMIN] = 1;
        new_attr.special_codes[SpecialCodeIndex::VTIME] = 0;
        new_attr.input_modes.remove(
            InputModes::IGNBRK
                | InputModes::BRKINT
                | InputModes::PARMRK
                | InputModes::ISTRIP
                | InputModes::INLCR
                | InputModes::IGNCR
                | InputModes::ICRNL
                | InputModes::IXON,
        );
        new_attr.output_modes.remove(OutputModes::OPOST);
        new_attr.local_modes.remove(
            LocalModes::ECHO
                | LocalModes::ECHONL
                | LocalModes::ICANON
                | LocalModes::ISIG
                | LocalModes::IEXTEN,
        );
        new_attr
            .control_modes
            .remove(ControlModes::CSIZE | ControlModes::PARENB);
        new_attr.control_modes.insert(ControlModes::CS8);
        tcsetattr(stdout(), OptionalActions::Drain, &new_attr)?;
        Ok(RawTerminal(old_attr))
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        _ = tcsetattr(stdout(), OptionalActions::Drain, &self.0);
    }
}

pub fn run_io_host(listener: UnixListener, is_tty: bool) -> Result<u8> {
    let mut stdin = unsafe { ManuallyDrop::new(File::from_raw_fd(0)) };
    let mut stdout = unsafe { ManuallyDrop::new(File::from_raw_fd(1)) };
    let mut stderr = unsafe { ManuallyDrop::new(File::from_raw_fd(2)) };
    let mut remote = listener.accept()?.0;
    let epoll = Epoll::new(EpollCreateFlags::empty())?;
    let signalfd = SignalFd::new(&SigSet::from(Signal::SIGWINCH))?;
    epoll.add(&remote, EpollEvent::new(EpollFlags::EPOLLIN, 1))?;
    epoll.add(stdin.as_fd(), EpollEvent::new(EpollFlags::EPOLLIN, 2))?;
    if is_tty {
        epoll.add(&signalfd, EpollEvent::new(EpollFlags::EPOLLIN, 3))?;
        sigprocmask(
            SigmaskHow::SIG_BLOCK,
            Some(&SigSet::from(Signal::SIGWINCH)),
            None,
        )?;
        update_size(&mut remote)?;
    }
    loop {
        let mut evts = [EpollEvent::empty()];
        match epoll.wait(&mut evts, EpollTimeout::NONE) {
            Err(Errno::EINTR) | Ok(0) => {
                continue;
            },
            Ok(_) => {},
            e => {
                e.unwrap();
            },
        }
        match evts[0].data() {
            1 => {
                if let Some(exit) =
                    process_remote_msg(&mut remote, is_tty, &mut stdout, &mut stderr)?
                {
                    break Ok(exit);
                }
            },
            2 => process_stdin(&mut remote, &epoll, &mut stdin)?,
            3 => {
                if signalfd.read_signal()?.is_some() {
                    update_size(&mut remote)?;
                }
            },
            _ => unreachable!(),
        }
    }
}
