import joblib
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.ensemble import VotingClassifier
import lightgbm as lgb
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import time




# List of models
models = {
    "Random_Forest": RandomForestClassifier(n_estimators=100),
    "XGBoost": XGBClassifier(n_estimators=100),
    "LightGBM": LGBMClassifier(n_estimators=100),
    "SVM": SVC(),
    "Naive_Bayes": GaussianNB(),
    "KNN": KNeighborsClassifier(n_neighbors=5),
    "Logistic_Regression": LogisticRegression()
}


def train_static():
    # Load static dataset
    static_data = pd.read_csv("/datasets/static/data_file.csv")
    X_static = static_data.drop(columns=["md5Hash", "Benign", "FileName"])  # Drop ID & Label
    y_static = static_data["Benign"]

    # Train/Test Split
    X_train_static, X_test_static, y_train_static, y_test_static = train_test_split(X_static, y_static, test_size=0.2, random_state=42)
    results_static = []

    # Train Static Model
    for name, model in models.items():
        start_time = time.time()
        model.fit(X_train_static, y_train_static)  # Train model
        y_pred = model.predict(X_test_static)  # Make predictions
        end_time = time.time()
        
        # Evaluate metrics
        accuracy = accuracy_score(y_test_static, y_pred)
        precision = precision_score(y_test_static, y_pred)
        recall = recall_score(y_test_static, y_pred)
        f1 = f1_score(y_test_static, y_pred)
        training_time = end_time - start_time
        # model_size = joblib.dump(model, f"/home/om/D/College/RM/models/{name}_static.pkl")  # Save model
        
        results_static.append((name, accuracy, precision, recall, f1, training_time))

    print("STATIC MODEL SAVED")
    # Convert results to DataFrame
    df_results_static = pd.DataFrame(results_static, columns=["Model", "Accuracy", "Precision", "Recall", "F1 Score", "Training Time (s)"])
    df_results_static.to_csv("static_stats.csv")
    print(df_results_static)

# static_model = RandomForestClassifier(n_estimators=100, random_state=42)
# static_model.fit(X_train_static, y_train_static)

# joblib.dump(static_model,"/home/om/D/College/RM/datasets/static_model.pkl")

def train_dynamic():
#    Load dynamic dataset
    dynamic_data = pd.read_csv("/datasets/MalMem2022.csv")
    X_dynamic = dynamic_data.drop(columns=["Filename", "Category","Class","label"])  # Drop ID & Label
    y_dynamic = dynamic_data["label"]

    # Train/Test Split
    X_train_dynamic, X_test_dynamic, y_train_dynamic, y_test_dynamic = train_test_split(X_dynamic, y_dynamic, test_size=0.2, random_state=42)

    # Train Dynamic Model
    results_dynamic = []

    # Train Static Model
    for name, model in models.items():
        start_time = time.time()
        model.fit(X_train_dynamic, y_train_dynamic)  # Train model
        y_pred = model.predict(X_test_dynamic)  # Make predictions
        end_time = time.time()
        
        # Evaluate metrics
        accuracy = accuracy_score(y_test_dynamic, y_pred)
        precision = precision_score(y_test_dynamic, y_pred)
        recall = recall_score(y_test_dynamic, y_pred)
        f1 = f1_score(y_test_dynamic, y_pred)
        training_time = end_time - start_time
        # model_size = joblib.dump(model, f"/home/om/D/College/RM/models/{name}_dynamic.pkl")  # Save model
        
        results_dynamic.append((name, accuracy, precision, recall, f1, training_time))

    print("DYNAMIC MODEL SAVED")
    # Convert results to DataFrame
    df_results_dynamic = pd.DataFrame(results_dynamic, columns=["Model", "Accuracy", "Precision", "Recall", "F1 Score", "Training Time (s)"])
    df_results_dynamic.to_csv("dynamic_stats.csv")
    print(df_results_dynamic)




# Train Network Model
def train_network():
    # Load network dataset
    network_data = pd.read_csv("/datasets/CTU-IoT_clean.csv")
    X_network = network_data.drop(columns=["id.orig_h", "id.resp_h", "label"])  # Drop IDs & Labels
    y_network = network_data["label"]

    # Train/Test Split
    X_train_network, X_test_network, y_train_network, y_test_network = train_test_split(X_network, y_network, test_size=0.2, random_state=42)
    # Store results
    results_network = []

    for name, model in models.items():
        start_time = time.time()
        model.fit(X_train_network, y_train_network)  # Train model
        y_pred = model.predict(X_test_network)  # Make predictions
        end_time = time.time()
        
        # Evaluate metrics
        accuracy = accuracy_score(y_test_network, y_pred)
        precision = precision_score(y_test_network, y_pred)
        recall = recall_score(y_test_network, y_pred)
        f1 = f1_score(y_test_network, y_pred)
        training_time = end_time - start_time
        # model_size = joblib.dump(model, f"/home/om/D/College/RM/models/{name}_network.pkl")  # Save model
        
        results_network.append((name, accuracy, precision, recall, f1, training_time))

    print("NETWORK MODEL SAVED")
    # Convert results to DataFrame
    df_results_network = pd.DataFrame(results_network, columns=["Model", "Accuracy", "Precision", "Recall", "F1 Score", "Training Time (s)"])
    df_results_network.to_csv("network_stats.csv")
    print(df_results_network)

# network_model = lgb.LGBMClassifier(n_estimators=100, random_state=42)
# network_model.fit(X_train_network, y_train_network)

# joblib.dump(network_model,"/home/om/D/College/RM/datasets/network_model.pkl")

def main():
    train_network()
    train_static()
    train_dynamic()

main()
""" 
# Combine models in an ensemble
ensemble = VotingClassifier(estimators=[
    ('static', static_model),
    ('dynamic', dynamic_model),
    ('network', network_model)
], voting='hard')

# Train ensemble model on combined dataset
X_combined_train = X_train_static.join(X_train_dynamic, how="outer", rsuffix="_dyn").join(X_train_network, how="outer", rsuffix="_net")
y_combined_train = y_train_static  # Use static labels as base

X_combined_test = X_test_static.join(X_test_dynamic, how="outer", rsuffix="_dyn").join(X_test_network, how="outer", rsuffix="_net")
y_combined_test = y_test_static

if len(y_combined_train) > len(X_combined_train):
    y_combined_train = y_combined_train[:len(X_combined_train)]
elif len(y_combined_train) < len(X_combined_train):
    X_combined_train = X_combined_train[:len(y_combined_train)]

print(X_combined_train.fillna(0),y_combined_train.fillna(0))
ensemble.fit(X_combined_train.fillna(0), y_combined_train.fillna(0))

# Evaluate accuracy

y_pred = ensemble.predict(X_combined_test.fillna(0))
print("Ensemble Accuracy:", accuracy_score(y_combined_test, y_pred))


# Save trained ensemble model
joblib.dump(ensemble, "/models/ransomware_ensemble_model.pkl")

print("Model saved successfully!")

 """
