# MINI-Disassembler 🚀

A lightweight and simple disassembler, initially developed out of curiosity, bcz i was bored, this took me 5 days, but i want to keep up updating it <3

## ✨ Key Features

*   **📊 Graphical Control Flow View:** Generates and displays function control flow graphs using Graphviz, making program logic easier to understand.
*   **💻 Sequential Instruction Listing:** Presents disassembled instructions in a clear, sequential format.

## 🛠️ Technologies & Libraries Used

This project utilizes the following libraries and tools:

*   **Graphical User Interface (UI):**
    *   [ImGui](https://github.com/ocornut/imgui): Bloat-free graphical user interface library for C++.
    *   [ImGui Standalone](https://github.com/adamhlt/ImGui-Standalone): We dont want the window right?
*   **Disassembly Engine:**
    *   [Zydis](https://github.com/zyantific/zydis) (v3.2.1): Fast and lightweight x86/x86-64 disassembler library.
    *   [Zycore](https://github.com/zyantific/zycore) (v1.3.0): Utility library for Zydis.
*   **Graph Visualization:**
    *   [Graphviz](https://graphviz.org/) (v10.0.1): Graph visualization software and libraries.
*   **Package Manager:**
    *   [VCPKG](https://github.com/microsoft/vcpkg): Used to install and manage dependencies.

## ⚙️ Prerequisites

*   [Git](https://git-scm.com/) (if you want or else you can download source directly from here btw)
*   [VCPKG](https://github.com/microsoft/vcpkg#quick-start-windows) installed and integrated.
*   [Visual Studio](https://visualstudio.microsoft.com/) with the "Desktop development with C++" workload installed.

## 🔧 Installation & Building (Windows x64)

Follow these steps to build the project:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/MINI-Disassembler.git # Replace with your actual repo link
    cd MINI-Disassembler
    ```

2.  **Install Dependencies using VCPKG:**
    *   **Important Note for Zydis v3.2.1:** VCPKG might have a newer version of Zydis by default. To install the specific version 3.2.1 required by this project, you need to manually acquire the correct port files:
        1.  Go to the [VCPKG GitHub repository history](https://github.com/microsoft/vcpkg/commits/master/ports/zydis).
        2.  Find the commit corresponding to Zydis version 3.2.1.
        3.  Download the `ports/zydis` and `ports/zycore` folder from that specific commit.
        4.  Replace the existing `zydis/zycore` folders inside your local VCPKG installation directory with the downloaded version.
    *   Now, install the dependencies:
        ```bash
        # Ensure you are in your VCPKG directory or have it in your PATH
        vcpkg install zydis
        vcpkg install graphviz
        ```

3.  **Compile the Project using Visual Studio:**
    *   Open the project folder or solution file (`.sln`) in Visual Studio.
    *   Select the `Release` configuration and `x64` platform from the configuration dropdowns.
    *   Build the solution

## 🚀 How to Use

1.  Run the compiled executable (e.g., `x64/Release/MINI-Disassembler.exe`).

## 📸 Preview

Here are some screenshots of MINI-Disassembler in action:

*Figure 1: Processes*
![Processes](https://i.imgur.com/2EDnaNo.png)

*Figure 2: Modules*
![Modules](https://i.imgur.com/Zla7zaj.png)

*Figure 3: Instructions View*
![Instructions View](https://i.imgur.com/ydpwf6h.png)

*Figure 4: Another View*
![Another View](https://i.imgur.com/BlRV1Yg.png)

## 🤝 Contributing

Contributions are welcome! If you have ideas for improvements, bug fixes, or new features:

1.  Fork the project.
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

You can also simply open an issue with the tag "enhancement" or "bug".
