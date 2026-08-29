from executor import evaluate_expression

@app.post('/evaluate')
def run(user_input):
    return evaluate_expression(user_input)
