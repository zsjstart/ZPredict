def rela_diff(a, b, MAX):
	return (b + MAX - a)%MAX

def diff(a, b):
	return (b-a)
	
def difference(data, order, MAX):
	diffs = []
	for i in range(order, len(data)):
		diff = rela_diff(data[i-order], data[i], MAX)
		#if diff <0: diff = diff + 65536
		diffs.append(diff)
	return diffs
			
def correct(data, y_pred, MAX):
	pred_data = []
	y_pred = list(y_pred.flatten())
	i_start = len(y_pred)
	for i in range(-i_start, 0):
		d = (data[i-1] + y_pred[i])%MAX
		
		pred_data.append(d)
	return pred_data
	
def correct02(data, y_pred, MAX):
	pred_data = []
	y_pred = list(y_pred.flatten())
	i_start = len(y_pred)
	for i in range(-i_start, 0):
		d = (data[i] + y_pred[i])%MAX
		pred_data.append(d)
	return pred_data

def denormalize(y, maximum, minimum):
    final_value = y*(maximum - minimum) + minimum
    return final_value

	
