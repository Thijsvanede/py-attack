from py_attack import ATTACK

if __name__ == "__main__":
    # Download latest ATTACK framework
    attack = ATTACK.download()

    #
    while True:
        concept = input("Find related concepts for ID (e.g., T1087): ")

        for related in sorted(attack.related_concepts(concept, depth=1)):
            print('  {}'.format(related))
        print()
