import json

graph = json.loads(open('graph.json', 'r').read())

current = []


def dfs(state, position):
    if position == 16:
        print("".join(current))

    for next_char, next_state in graph[state]:
        current.append(chr(next_char))
        dfs(next_state, position + 1)
        current.pop()


dfs(0, 0)