from tdh2 import dealer, serialize1, group
import argparse
import pickle

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('players', help='The number of players')
    parser.add_argument('k', help='k')
    parser.add_argument('fname', help='fname')
    args = parser.parse_args()
    players = int(args.players)
    if args.k:
        k = int(args.k)
    else:
        k = players / 2 # N - 2 * t
    fname = args.fname
    PK, SKs, gg = dealer(players=players, k=k)
    content = (PK.l, PK.k, serialize1(PK.VK), [serialize1(VKp) for VKp in PK.VKs],
    [(SK.i, serialize1(SK.SK)) for SK in SKs], serialize1(gg))

#print (pickle.dumps(content))
    with open(fname, "wb") as f:
        pickle.dump(content, f)

if __name__ == '__main__':
    main()