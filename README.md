
# Ransomware Detection App

This repository contains a Windows desktop application that detects ransomware based on network traffic. The app uses static network features extracted from executed .exe files and classifies them using a pre-trained XGBoost model. The system is designed to be lightweight and suitable for real-time detection in IoT or edge devices.

## Table of Contents
- [Pre-requisites](#pre-requisites)
- [Setup](#setup)
- [Application Workflow](#application-workflow)
- [File Structure](#file-structure)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [License](#license)

## Pre-requisites
Before running the application, ensure you have the following:

- **Windows 10 VirtualBox**  
  Set up a Windows 10 VirtualBox to run the executable files safely.

- **Python 3**  
  Make sure Python 3 is installed in your VirtualBox.

- **Wireshark**  
  Wireshark (with TShark.exe in PATH Environment variables) must be installed to capture network traffic.

- **Other Dependencies**  
  All other required Python packages are listed in `requirements.txt` and will be installed via:
  ```bash
  pip install -r requirements.txt
  ```

## Setup
1. Clone the repository.
2. Install the dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up your Windows 10 VirtualBox environment with Python 3 and Wireshark.

## Application Workflow
The application follows this pipeline:
1. **Upload Executable**:  
   - The user selects an `.exe` file via the GUI.
2. **Execute File**:  
   - The file is executed inside the VirtualBox environment.
3. **Network Capture**:  
   - Wireshark (via PyShark) captures network traffic during the file execution and saves it as `network_features.csv`.
4. **Preprocessing**:  
   - The captured CSV data is cleaned and preprocessed to extract the required static network features.
5. **Prediction**:  
   - The preprocessed features are fed into a pre-trained XGBoost model.
6. **Result Display**:  
   - The GUI shows the final prediction: either "Benign" or "Malware".

## File Structure
```
/home/om/D/RM/
├── app.py                  # Main application (GUI) for file upload and detection
├── train.py                # Script for training models (if needed)

├── requirements.txt    # Required Python packages
├── visualise.py        # Code for model statistics and visualizations
├── model_stats.csv     # CSV file containing model performance stats
├── models/                 # Folder containing saved models (e.g., xgboost_model.pkl, static_model.pkl, dynamic_model.pkl, network_model.pkl)
└── datasets/               # Folder containing datasets used for training/testing
```

## Usage
1. **Run the Application**:
   ```bash
   python app.py
   ```
2. **Upload File**:  
   - Use the GUI to upload an `.exe` file.
3. **Execution & Capture**:  
   - The file is executed in the VirtualBox.
   - Network traffic is captured and saved as `network_features.csv`.
4. **Prediction**:  
   - Preprocessing is applied to the captured data.
   - The XGBoost model is used to predict if the file is benign or malware.
5. **Result Display**:  
   - The result is shown on the GUI.

## Screenshots
- **Home Screen**:
  ![home]('screenshots/home_screen.jpeg')
- **File Upload Dialog**:
- 
- **Analysis in Progress**:  
  ![home]('screenshots/analysis.jpeg')
- **Result Display**:  
  ![home]('screenshots/result_screen.jpeg')

## License
This project is licensed under the [MIT License](LICENSE).



