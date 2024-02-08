import pandas as pd
import json

def json_to_df(json_file, header=None):
    with open(json_file, 'r') as f:
        data = json.load(f)
    df = pd.DataFrame.from_dict(data, orient='index')
    if header:
        df = pd.concat([pd.DataFrame([header], columns=['Header']), df])
    return df

dependencies_df = json_to_df('dependencies.json')
devdependencies_df = json_to_df('dev-dependencies.json')

# Save the combined data to a single Excel file
with pd.ExcelWriter('combined_dependencies.xlsx') as writer:
    dependencies_df.to_excel(writer, sheet_name='Dependencies', index=False)
    devdependencies_df.to_excel(writer, sheet_name='Dev Dependencies', index=False)
