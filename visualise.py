import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.preprocessing import LabelEncoder

def network():
    # === Load Network Dataset ===
    file_path = "/home/om/D/College/RM/datasets/CTU-IoT_clean.csv"  # Update path if needed
    df = pd.read_csv(file_path)

    # === Drop Non-Numeric Columns (IP Addresses Not Useful for ML) ===
    df.drop(columns=["id.orig_h", "id.resp_h"], errors="ignore", inplace=True)

    # === Compute Correlation Matrix ===
    correlation_matrix = df.corr()

    # === Display Correlation with Target Variable (`label`) ===
    target_correlation = correlation_matrix["label"].sort_values(ascending=False)
    print("\n🔹 Correlation of Features with the Target Variable (label):")
    print(target_correlation)

    # === Plot Heatmap of Feature Correlations ===
    plt.figure(figsize=(12, 8))
    sns.heatmap(correlation_matrix, annot=False, cmap="coolwarm", linewidths=0.5)
    plt.title("Feature Correlation Heatmap")
    plt.show()

    # === Plot Most Important Features Affecting the Target (`label`) ===
    top_features = target_correlation[1:11]  # Exclude 'label' itself
    plt.figure(figsize=(10, 5))
    sns.barplot(x=top_features.index, y=top_features.values, palette="viridis")
    plt.xticks(rotation=45)
    plt.title("Top Features Affecting Ransomware Detection (Network Data)")
    plt.ylabel("Correlation with label")
    plt.show()

def static():
        # Load static dataset
    df = pd.read_csv("/home/om/D/College/RM/datasets/static/data_file.csv")
    df.drop(columns=["md5Hash", "FileName"], inplace=True)  # Drop ID & Label
    # === Compute Correlation Matrix ===
    correlation_matrix = df.corr()

    # === Display Correlation with Target Variable (`label`) ===
    target_correlation = correlation_matrix["Benign"].sort_values(ascending=False)
    print("\n🔹 Correlation of Features with the Target Variable (label):")
    print(target_correlation)

    # === Plot Heatmap of Feature Correlations ===
    plt.figure(figsize=(12, 8))
    sns.heatmap(correlation_matrix, annot=False, cmap="coolwarm", linewidths=0.5)
    plt.title("Feature Correlation Heatmap")
    plt.show()

    # === Plot Most Important Features Affecting the Target (`label`) ===
    top_features = target_correlation[1:11]  # Exclude 'label' itself
    plt.figure(figsize=(10, 5))
    sns.barplot(x=top_features.index, y=top_features.values, palette="viridis")
    plt.xticks(rotation=45)
    plt.title("Top Features Affecting Ransomware Detection (Static Data)")
    plt.ylabel("Correlation with label")
    plt.show()

def dynamic():

    
    df = pd.read_csv("/home/om/D/College/RM/datasets/MalMem2022.csv")
    df.drop(columns=["Filename", "Category","Class"],inplace=True)

    correlation_matrix = df.corr()
    # === Display Correlation with Target Variable (`label`) ===
    target_correlation = correlation_matrix["label"].sort_values(ascending=False)
    print("\n🔹 Correlation of Features with the Target Variable (label):")
    print(target_correlation)

    # === Plot Heatmap of Feature Correlations ===
    plt.figure(figsize=(12, 8))
    sns.heatmap(correlation_matrix, annot=False, cmap="coolwarm", linewidths=0.5)
    plt.title("Feature Correlation Heatmap")
    plt.show()

    # === Plot Most Important Features Affecting the Target (`label`) ===
    top_features = target_correlation[1:11]  # Exclude 'label' itself
    plt.figure(figsize=(10, 5))
    sns.barplot(x=top_features.index, y=top_features.values, palette="viridis")
    plt.xticks(rotation=45)
    plt.title("Top Features Affecting Ransomware Detection (Dynamic Data)")
    plt.ylabel("Correlation with label")
    plt.show()


network()