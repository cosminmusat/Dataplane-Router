#include "queue.h"
#include "list.h"
#include <stdlib.h>
#include <assert.h>

struct queue
{
	list head;
	list tail;
	unsigned int no_elem;
};

queue create_queue(void)
{
	queue q = malloc(sizeof(struct queue));
	q->head = q->tail = NULL;
	q->no_elem = 0;
	return q;
}

int queue_empty(queue q)
{
	return q->head == NULL;
}

void queue_enq(queue q, void *element)
{
	if(queue_empty(q)) {
		q->head = q->tail = constr(element, NULL);
	} else {
		q->tail->next = constr(element, NULL);
		q->tail = q->tail->next;
	}
	++q->no_elem;
}

void *queue_deq(queue q)
{
	assert(!queue_empty(q));
	{
		void *temp = q->head->element;
		q->head = cdr_and_free(q->head);
		return temp;
	}
	--q->no_elem;
}

unsigned int queue_size(queue q) {
	return q->no_elem;
}