
# THOR APT Launcher

Công cụ rà quét máy chủ dựa trên các IOCs đã biết và các quy tắc YARA để phát hiện mã độc, phát hiện tấn công APT. Công cụ được xây dựng dựa trên bộ THOR/THOR-Lite APT Scanner.


## Các tính năng

- Quét dựa theo các modules
- Hỗ trợ đa nền tảng: Windows, Linux, MacOSX
- Mã hóa các IOCs, YARA rules trước khi đóng gói công cụ
- Cập nhật tự động IOCs và YARA rules từ Nextron Systems GmbH
- Có thể thêm IOCs và YARA rules tự viết.
- Tùy chọn xuất báo cáo nhiều định dạng: Text, HTML, JSON, CSV,.v.v..
- Tùy chỉnh cấu hình mức độ sử dụng CPU, bộ nhớ, kích thước tệp quét,.v.v..
- and more..!


## THOR và THOR-Lite APT Scanner

Phiên bản **THOR** là bản thương mại.
- **Các module:** AtJobs, Autoruns, DNSCache, EnvCheck, Eventlog, Events, Filescan, Firewall, Hosts, HotfixCheck, LSASessions, LoggedIn, Mutex, NetworkSessions, NetworkShares, OpenFiles, Pipes, ProcessCheck, RegistryChecks, Rootkit, SHIMCache, ScheduledTasks, ServiceCheck, UserDir, Users, WMIStartup, DeepDive, Dropzone, MFT

- **Các tính năng:** Amcache, Archive, ArchiveScan, AtJobs, Bifrost2, C2, CPULimit, CheckString, DoublePulsar, EVTX, ExeDecompress, FilenameIOCs, Filescan, GroupsXML, KeywordIOCs, Lnk, LogScan, Prefetch, ProcessConnections, ProcessHandles, RegistryHive, Rescontrol, SHIMCache, SignalHandler, Stix, TeamViewer, ThorDB, Timestomp, VulnerabilityCheck, WER, WMIPersistence, WebdirScan, Yara, Action, Bifrost, DumpScan, Sigma

Phiên bản **THOR-Lite** là bản miễn phí, cần phải đăng ký để có thể download. Bản THOR-Lite sẽ bị hạn chế hơn bản THOR. Chỉ còn:
- **Các module:** Filescan, ProcessCheck, Autoruns
- **Các tính năng:** Action, Bifrost, C2, CPULimit, CheckString, DumpScan, FilenameIOCs, KeywordIOCs, LogScan, ProcessConnections, ProcessHandles, Rescontrol, ThorDB, Yara


## Cài đặt môi trường ứng dụng
Download và cài đặt Python 3 tại: https://www.python.org/downloads. Hiện tại hỗ trợ phiên bản Python 3.6 trở lên.

Kiểm tra vị trí cài đặt Python 3 trên máy:
```bash
# Windows
$ where python
  
# Linux và MacOSX
$ which python3
```

Tạo Virtual Python Environment: Nhằm mục đích chạy ứng dụng Python của chúng ta trong một môi trường an toàn, cô lập với hệ thống thật, tránh được các xung đột hay lỗi giữa các phiên bản phần mềm, thư viện.

```bash
$ pip3 install virtualenv

# Windows
$ mkdir my-project & cd my-project
$ virtualenv -p c:\path\to\python.exe venv

# Linux và MacOSX
$ mkdir my-project && cd my-project
$ virtualenv -p /path/to/python3 venv
```

Kích hoạt Virtual Python Environment:
```bash
# Windows:
$ venv\Scripts\activate

# Linux và MacOS:
$ source venv/bin/activate
```

Sao chép mã nguồn:
```bash
$ git clone https://github.com/hailehong95/THOR-Launcher.git
```

Cài đặt các gói phụ thuộc:
```bash
(venv) $ pip install -r requirements.txt
```
## Đóng gói ứng dụng

### THOR Utility

Là tiện ích dùng để đóng gói bộ **THOR/THOR-Lite** thành một tệp thực thi duy nhất, thuận tiện cho việc phân phối đến các client khi rà quét.
```bash
(venv) $ python thor-util.py
Usage: thor-util.py [OPTIONS] COMMAND [ARGS]...

  A CLI Utility for THOR APT Scanner by HaiLH

Options:
  --help  Show this message and exit.

Commands:
  build      Build THOR APT Scanner package
  clean      Clean all temporary working files
  extract    Extract THOR packs
  keygen     RSA keys generator
  license    Add THOR license
  make       Create THOR APT Scanner bundle
  remove     Remove THOR optional binaries and dirs
  rename     Rename THOR binaries
  rsakey     Add encryption key
  signature  Add custom signatures
  update     Update signatures
  upgrade    Upgrade THOR and signatures
  version    Show Utility version
```

Giải thích một số command:
- **extract**: Giải nén bộ **THOR** phù hợp theo hệ điều hành đang chạy.
- **license**: Thêm giấy phép hoạt động của bộ **THOR**.
- **rsakey**: Thêm khóa mật mã RSA vào bộ **THOR**. Dùng để mã hóa các tệp báo cáo sau khi rà quét xong.
- **signature**: Mã hóa các YARA rules tùy chỉnh tự viết bằng khóa RSA của THOR sau đó thêm vào bộ **THOR**.
- **update**: Cập nhật các signature từ Nextron Systems GmbH.
- **upgrade**: Cập nhật signature và bộ **THOR** từ Nextron Systems GmbH.
- **remove**: Xóa các thư mục, tệp tin không cần thiết trong bộ **THOR** trước khi đóng gói.
- **rename**: Đổi tên một số tệp tin chương trình trong bộ **THOR** trước khi đóng gói.
- **keygen**: Sinh cặp khóa RSA. Khóa này dùng để mã hóa các tệp báo cáo.
- **make**: Tự động tất cả các bước cần thiết để có thể tạo một bộ **THOR** trước khi đóng gói ứng dụng. Mặc định sẽ tạo bộ **THOR** phiên bản 64-bits.
- **build**: Đóng gói ứng dụng, tạo một tệp thực thi duy nhất.
- **clean**: Xóa bộ **THOR** và các tệp liên quan đã giải nén.


### THOR APT Scanner
Thực chất là một **CLI Launcher** sẽ gọi các **THOR binaries** để rà quét. Tệp thực thi cuối cùng sẽ được nhúng các binaries này và các iocs, yara rules kèm với bộ thông dịch Python.

```bash
$ thor-apt-scanner.exe
Usage: thor-apt-scanner.exe [OPTIONS] COMMAND [ARGS]...

  A CLI Launcher for the THOR APT Scanner by HaiLH

Options:
  --help  Show this message and exit.

Commands:
  all      SCAN ALL available modules
  auto     SCAN Autoruns: Auto-starting programs
  file     SCAN Files: Scan a specific file path
  proc     SCAN Process: Process images and connections
  version  SHOW THOR APT Scanner version
```
### Các bước đóng gói ứng dụng

1. Nhận **THOR/THOR-Lite**: Gửi yêu cầu đến **Nextron Systems GmbH** tại: https://www.nextron-systems.com/thor-lite/download. Sau đó đợi họ gửi link download kèm tệp license key qua email. Tải về và lưu bộ THOR (**.zip**) vào thư mục: [**./thor_packs/**](./thor_packs). Tương tự tệp license (***.lic**) lưu vào thư mục: [**./thor_license/**](./thor_license)

    **YARA Rules**: Thêm các rule tự viết vào thư mục: [**./signatures/**](./signatures)

    **UPX Packer** (tùy chọn): Sử dụng **UPX** để nén cũng như là thêm một bước bảo vệ tệp thực thi. Download tại: https://github.com/upx/upx/releases và đặt vào thư mục tương ứng trong: [**./packer/**](./packer)

2. Sinh cặp khóa RSA (tùy chọn)
    ```bash
    (venv) $ python thor-util.py keygen --keyname "key" --length 4096
    ```
    ![image info](./assets/keygen.png)

3. Tạo bộ **THOR** tự động.
    ```bash
    (venv) $ python thor-util.py make
    ```
    ![image info](./assets/make.png)


4. Đóng gói **THOR APT Scanner**.
    ```bash
    (venv) $ python thor-util.py build
    ```
    ![image info](./assets/build.png)


5. Thử nghiệm
    ```bash
    $ thor-apt-scanner.exe
    ```
    ![image info](./assets/usage.png)

    Sau khi hoàn tất rà quét, các tệp báo cáo sẽ được mã hóa và nén lại thành một tệp ***.zip**.

## Các hệ thống đã chạy thử nghiệm

- Microsoft Windows: 7, 8/8.1, 10, 2012, 2016, 2019
- Linux: Ubuntu 18.04 LTS, Ubuntu 20.04 LTS
- MacOSX: 10.16 (Big Sur)
