#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "allocate.h"

#define DEBUG_MALLOC
#define MEMORY_USAGE

#define MAGIC_NUMBER 0x12345678

#if defined DEBUG_MALLOC

struct chunkHeader *chunkList = NULL;

struct chunkHeader
{
	struct chunkHeader *next;
	unsigned int length;
	int tag;
	unsigned int magicNumber;
};

struct chunkTrailer
{
	unsigned int magicNumber;
};


#if defined MEMORY_USAGE

struct memoryUsage *memoryList = NULL;


struct memoryUsage
{
	struct memoryUsage *next;
	unsigned int length;
	unsigned int counter;
	int tag;
};


void addMemory( unsigned int length, int tag ) {

	struct memoryUsage *walker;


	for ( walker = memoryList; walker != NULL; walker = walker->next ) {

		if ( walker->tag == tag ) {

			walker->counter++;
			break;

		}

	}

	if ( walker == NULL ) {

		walker = malloc( sizeof(struct memoryUsage) );

		walker->length = length;
		walker->tag = tag;
		walker->counter = 1;

		walker->next = memoryList;
		memoryList = walker;

	}

}


void removeMemory( int tag, int freetag ) {

	struct memoryUsage *walker;


	for ( walker = memoryList; walker != NULL; walker = walker->next ) {

		if ( walker->tag == tag ) {

			if ( walker->counter == 0 ) {

				fprintf( stderr, "Freeing more memory than was allocated: malloc tag = %d, free tag = %d\n", tag, freetag );
				exit(1);

			}

			walker->counter--;
			break;

		}

	}

	if ( walker == NULL ) {

		fprintf( stderr, "Freeing memory that was never allocated: malloc tag = %d, free tag = %d\n", tag, freetag );
		exit(1);

	}

}

#endif



void checkIntegrity(void)
{
	struct chunkHeader *walker;
	struct chunkTrailer *chunkTrailer;
	unsigned char *memory;


#if defined MEMORY_USAGE

	struct memoryUsage *memoryWalker;

	fprintf( stderr, "Memory usage information:\n" );

	for ( memoryWalker = memoryList; memoryWalker != NULL; memoryWalker = memoryWalker->next ) {

		if ( memoryWalker->counter != 0 )
			fprintf( stderr, "   tag: %i, num malloc: %i, bytes per malloc: %i, total: %i\n", memoryWalker->tag, memoryWalker->counter, memoryWalker->length, memoryWalker->counter * memoryWalker->length );

	}

#endif

	for (walker = chunkList; walker != NULL; walker = walker->next)
	{
		if (walker->magicNumber != MAGIC_NUMBER)
		{
			fprintf(stderr, "Invalid magic number in header: %08x, malloc tag = %d\n", walker->magicNumber, walker->tag);
			exit(1);
		}

		memory = (unsigned char *)walker;

		chunkTrailer = (struct chunkTrailer *)(memory + sizeof(struct chunkHeader) + walker->length);

		if (chunkTrailer->magicNumber != MAGIC_NUMBER)
		{
			fprintf(stderr, "Invalid magic number in header: %08x, malloc tag = %d\n", chunkTrailer->magicNumber, walker->tag);
			exit(1);
		}
	}
}

void checkLeak(void)
{
	struct chunkHeader *walker;

	for (walker = chunkList; walker != NULL; walker = walker->next)
		fprintf(stderr, "Memory leak detected, malloc tag = %d\n", walker->tag);
}

void *debugMalloc(unsigned int length, int tag)
{
	unsigned char *memory;
	struct chunkHeader *chunkHeader;
	struct chunkTrailer *chunkTrailer;
	unsigned char *chunk;

// 	printf("sizeof(struct chunkHeader) = %u, sizeof (struct chunkTrailer) = %u\n", sizeof (struct chunkHeader), sizeof (struct chunkTrailer));

	memory = malloc(length + sizeof(struct chunkHeader) + sizeof(struct chunkTrailer));

	if (memory == NULL)
	{
		fprintf(stderr, "Cannot allocate %u bytes, malloc tag = %d\n", (unsigned int)(length + sizeof(struct chunkHeader) + sizeof(struct chunkTrailer)), tag);
		exit(1);
	}

	chunkHeader = (struct chunkHeader *)memory;
	chunk = memory + sizeof(struct chunkHeader);
	chunkTrailer = (struct chunkTrailer *)(memory + sizeof(struct chunkHeader) + length);

	chunkHeader->length = length;
	chunkHeader->tag = tag;
	chunkHeader->magicNumber = MAGIC_NUMBER;

	chunkTrailer->magicNumber = MAGIC_NUMBER;

	chunkHeader->next = chunkList;
	chunkList = chunkHeader;

#if defined MEMORY_USAGE

	addMemory( length, tag );

#endif

	return chunk;
}

void *debugRealloc(void *memoryParameter, unsigned int length, int tag)
{
	unsigned char *memory;
	struct chunkHeader *chunkHeader;
	struct chunkTrailer *chunkTrailer;
	unsigned char *result;
	unsigned int copyLength;

	if (memoryParameter) { /* if memoryParameter==NULL, realloc() should work like malloc() !! */
		memory = memoryParameter;
		chunkHeader = (struct chunkHeader *)(memory - sizeof(struct chunkHeader));

		if (chunkHeader->magicNumber != MAGIC_NUMBER)
		{
			fprintf(stderr, "Invalid magic number in header: %08x, malloc tag = %d\n", chunkHeader->magicNumber, chunkHeader->tag);
			exit(1);
		}

		chunkTrailer = (struct chunkTrailer *)(memory + chunkHeader->length);

		if (chunkTrailer->magicNumber != MAGIC_NUMBER)
		{
			fprintf(stderr, "Invalid magic number in header: %08x, malloc tag = %d\n", chunkTrailer->magicNumber, chunkHeader->tag);
			exit(1);
		}
	}


	result = debugMalloc(length, tag);
	if (memoryParameter) {
		copyLength = length;

		if (copyLength > chunkHeader->length)
			copyLength = chunkHeader->length;

		memcpy(result, memoryParameter, copyLength);
		debugFree(memoryParameter, 9999);
	}


	return result;
}

void debugFree(void *memoryParameter, int tag)
{
	unsigned char *memory;
	struct chunkHeader *chunkHeader;
	struct chunkTrailer *chunkTrailer;
	struct chunkHeader *walker;
	struct chunkHeader *previous;

	memory = memoryParameter;
	chunkHeader = (struct chunkHeader *)(memory - sizeof(struct chunkHeader));

	if (chunkHeader->magicNumber != MAGIC_NUMBER)
	{
		fprintf(stderr, "Invalid magic number in header: %08x, malloc tag = %d, free tag = %d\n", chunkHeader->magicNumber, chunkHeader->tag, tag);
		exit(1);
	}

	previous = NULL;

	for (walker = chunkList; walker != NULL; walker = walker->next)
	{
		if (walker == chunkHeader)
			break;

		previous = walker;
	}

	if (walker == NULL)
	{
		fprintf(stderr, "Double free detected, malloc tag = %d, free tag = %d\n", chunkHeader->tag, tag);
		exit(1);
	}

	if (previous == NULL)
		chunkList = walker->next;

	else
		previous->next = walker->next;

	chunkTrailer = (struct chunkTrailer *)(memory + chunkHeader->length);

	if (chunkTrailer->magicNumber != MAGIC_NUMBER)
	{
		fprintf(stderr, "Invalid magic number in header: %08x, malloc tag = %d, free tag = %d\n", chunkTrailer->magicNumber, chunkHeader->tag, tag);
		exit(1);
	}

#if defined MEMORY_USAGE

	removeMemory( chunkHeader->tag, tag );

#endif

	free(chunkHeader);

}

#else

void checkIntegrity(void)
{
}

void checkLeak(void)
{
}

void *debugMalloc(unsigned int length, int tag)
{
	void *result;

	result = malloc(length);

	if (result == NULL)
	{
		fprintf(stderr, "Cannot allocate %u bytes, malloc tag = %d\n", length, tag);
		exit(1);
	}

	return result;
}

void *debugRealloc(void *memory, unsigned int length, int tag)
{
	void *result;

	result = realloc(memory, length);

	if (result == NULL)
	{
		fprintf(stderr, "Cannot re-allocate %u bytes, malloc tag = %d\n", length, tag);
		exit(1);
	}

	return result;
}

void debugFree(void *memory, int tag)
{
	free(memory);
}

#endif
